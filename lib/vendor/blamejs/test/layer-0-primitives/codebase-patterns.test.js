"use strict";

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
      // Look for `length` mention in surrounding 5 lines (any
      // comparison: <, >, =, !=, !==, including the explicit-length
      // shape `s.length !== expectedLength`).
      var window = (lines[li-2] || "") + (lines[li-1] || "") +
                   line + (lines[li+1] || "") + (lines[li+2] || "");
      if (/\.length\s*[><=!]/.test(window)) continue;
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
      w.once("message", function (msg) { resolve(msg); w.terminate(); });
      w.once("error", reject);
      w.once("exit", function (code) {
        if (code !== 0 && code !== null) reject(new Error("shingle worker exited " + code));
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
      files: ["lib/api-key.js:issue", "lib/db-query.js:<top>", "lib/session.js:create"],
      reason: "Generic JS array helper / lambda shape — Object.keys(...).map(fn) + similar functional idioms appearing in any code that walks a column-or-key list.",
    },
    {
      files: ["lib/guard-filename.js:verifyExtractionPath", "lib/hal.js:resource", "lib/vault-aad.js:_canonicalize"],
      reason: "v0.13.13 — coincidental token shingle of the generic split-then-walk-segments idiom (`x.split(sep); for (...) { var seg = ...; if (...) throw/continue }`). guard-filename verifyExtractionPath walks path components refusing per-segment Windows-extraction hazards (reserved names / NTFS-ADS / trailing-dot); hal.js:resource builds a HAL resource by walking link/embedded keys; vault-aad.js:_canonicalize canonicalizes AAD key-value segments. Three unrelated domains (path safety / hypermedia link assembly / crypto AAD canonicalization) — no shared behaviour to extract; the only commonality is the universal split-and-loop control-flow shape.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/middleware/host-allowlist.js:create",
        "lib/middleware/require-auth.js:create",
        "lib/middleware/require-content-type.js:create",
        "lib/middleware/require-methods.js:create",
      ],
      reason: "v0.14.6 — the shared shingle is the uniform deny-path denyResponse() call-site shape. The deny-response WRITER is already extracted to lib/middleware/deny-response.js; what repeats here is each create()'s ctx object literal ({ onDeny, problem, status, info, problemCode, problemTitle, problemDetail, contentType, body }). Each middleware passes a DIFFERENT status (405 / 415 / 421 / 401), problemCode, title, default body and headers — the literal IS the per-middleware configuration the consumer-facing onDeny / problemDetails convention drives. Consolidating further would mean a config table strictly less readable than the inline ctx, and the per-middleware values are exactly the divergence the dup detector can't see.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/archive-read.js:_emitAudit",
        "lib/archive-tar-read.js:_emitAudit",
        "lib/archive.js:_emitAudit",
        "lib/http-client.js:_emitAudit",
      ],
      reason: "v0.12.7 + v0.12.8 — Per-module `_emitAudit(opts, action, outcome, metadata)` shape repeats across primitives that drop-silently emit to opts.audit.safeEmit if present. Each module's audit events carry a primitive-specific `action:` namespace (archive.read.*, archive.zip.*, archive.read.tar.*, http-client.*) + per-primitive metadata fields; consolidating would lose the namespace + force every consumer to import the same audit helper. Four-file repetition is the expected shape per `feedback_audit_safeEmit_per_module_emitAudit_shape`. archive-tar.js (write) does NOT carry _emitAudit — the read side lives in sibling archive-tar-read.js so the @primitive validator can pair both `b.archive.tar` (write) and `b.archive.read.tar` (read) cleanly.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/archive-read.js:_assertGuardMetadata",
        "lib/archive-tar-read.js:_assertGuardMetadata",
        "lib/auth/ciba.js:_registerInitialInterval",
        "lib/auth/oauth.js:exchangeToken",
        "lib/auth/oauth.js:pollDeviceCode",
        "lib/auth/oid4vci.js:createCredentialOffer",
        "lib/auth/oid4vci.js:exchangePreAuthorizedCode",
        "lib/restore-rollback.js:swap",
      ],
      reason: "v0.13.8 — the shared shingle is the framework's emit-audit-then-throw-typed-error idiom (validate/poll/guard → emit a namespaced audit row → throw a primitive-specific FrameworkError), not behaviour. archive-read/archive-tar-read `_assertGuardMetadata` run the b.guardArchive metadata cascade and throw ArchiveReadError/TarError (factored so disk `extract` + in-memory `extractEntries` share one refusal path); ciba/oauth/oid4vci are OAuth/OIDC device-code + credential-offer polling/exchange; restore-rollback.swap is the backup restore swap. Each body is domain-divergent (different inputs, error classes, audit namespaces); consolidating would couple unrelated subsystems to one helper.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/ai-quota.js:_emitAudit",
        "lib/ai-capability.js:_emitAudit",
        "lib/ai-dp.js:_emitAudit",
        "lib/cert.js:_emitAudit",
        "lib/mail-send-deliver.js:_auditEmit",
      ],
      reason: "v0.12.27 + v0.12.28 + v0.12.29 — per-module drop-silent audit-emit helper (`try { audit().safeEmit({ action, outcome, metadata }); } catch (_e) {}`). Same family as the archive / http-client _emitAudit cluster (feedback_audit_safeEmit_per_module_emitAudit_shape): ai-quota.js emits ai/quota-applied + ai/quota-exceeded, ai-capability.js emits ai/capability-routed + ai/capability-no-candidate, ai-dp.js emits dp/budget-consumed + dp/budget-exhausted, cert.js emits certificate-lifecycle events, mail-send-deliver.js emits delivery events. Each carries a primitive-specific `action:` namespace + metadata fields; consolidating would force a shared audit import and lose the per-primitive namespace operators grep for in audit logs.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/ai-quota.js:_validateStore",
        "lib/middleware/tus-upload.js:create",
        "lib/pagination.js:cursor",
        "lib/pagination.js:offset",
      ],
      reason: "v0.12.27 — defensive typeof-guard validation prelude (`if (!x || typeof x !== \"object\" || typeof x.fn !== \"function\") throw new <Error>(...)`). ai-quota._validateStore asserts the optional cross-node counter store exposes reserve / add / get / reset; tus-upload.create validates the resumable-upload opts shape; pagination.cursor / pagination.offset validate paging opts. Each throws a primitive-specific typed error (AiQuotaError / TusUploadError / PaginationError); the shingle is the typeof-guard cascade shape, not behaviour.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/ai-capability.js:create",
        "lib/ai-dp.js:budget",
        "lib/cert.js:create",
        "lib/mail-send-deliver.js:create",
        "lib/auth/sd-jwt-vc-holder.js:create",
      ],
      reason: "v0.12.28 + v0.12.29 — factory-primitive opts-validation prelude (`validateOpts.requireObject + validateOpts(allowedKeys) + per-field typed-error throws + closure-captured return`). ai-capability.create validates a model-descriptor registry + builds a router closure; ai-dp.budget validates a per-scope ε/δ budget + builds an accountant closure; cert.create / mail-send-deliver.create / sd-jwt-vc-holder.create each validate a distinct spec's opts (X.509 cert issuance / RFC 5321 SMTP send / SD-JWT-VC holder store). Each throws a primitive-specific typed error (AiCapabilityError / AiDpError / CertError / MailSendError / SdJwtVcError); the shingle is the create()-factory validation idiom, not behaviour. Same family as the v0.10.16 factory-primitive validateOpts cluster.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/ai-dp.js:mechanism",
        "lib/dora.js:_validateReportInput",
        "lib/config.js:loadDbBacked",
        "lib/guard-snapshot-envelope.js:validate",
      ],
      reason: "v0.12.29 — input-shape validation prelude (`validateOpts(allowedKeys) + chained typeof / range guards + typed-error throw`). ai-dp.mechanism validates a DP mechanism descriptor (type / sensitivity / epsilon / delta / bound); dora._validateReportInput validates a DORA Art. 17 incident report; config.loadDbBacked validates DB-backed config opts; guard-snapshot-envelope.validate validates a sealed snapshot envelope. Each enforces a distinct spec's field set with a primitive-specific typed error; the shingle is the validateOpts-then-guard idiom, not behaviour.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/cose.js:verify",
        "lib/cose.js:macVerify0",
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/break-glass.js:_validatePolicySet",
        "lib/calendar.js:validate",
        "lib/db.js:declareRequireDualControl",
        "lib/dsr.js:create",
        "lib/fedcm.js:wellKnown",
        "lib/middleware/assetlinks.js:create",
        "lib/network-heartbeat.js:start",
      ],
      reason: "v0.12.33 — opts / structure validation prelude (`validateOpts(allowedKeys) + chained required-field + typeof guards + typed-error throw`). cose.verify validates a COSE_Sign1 opts blob + decoded structure (RFC 9052); the peers each validate a distinct spec's shape (SD-JWT-VC issuer opts / break-glass policy set / JSCalendar object / DDL dual-control declaration / DSR request / FedCM well-known manifest / Android Asset Links / heartbeat config). Each throws a primitive-specific typed error; the shingle is the validateOpts-then-guard idiom, not behaviour. Same family as the v0.12.29 input-shape-validation cluster.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/json-path.js:_Parser",
        "lib/parsers/safe-ini.js:_unquote",
        "lib/template.js:_tokenizeExpr",
      ],
      reason: "v0.12.61 — recursive-descent / cursor-based tokenizers over DIFFERENT grammars: json-path._Parser walks the RFC 9535 JSONPath ABNF, safe-ini._unquote unwraps an INI quoted value, template._tokenizeExpr tokenizes a template expression. The shared shingle is the `index cursor + peek/advance + per-char dispatch` parser idiom; each consumes a distinct grammar with its own token set, so there is no shared parse behaviour to extract.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/link-header.js:_splitLinks",
        "lib/safe-ical.js:_splitUnquoted",
        "lib/safe-vcard.js:_splitUnquoted",
      ],
      reason: "v0.12.57 — format-specific delimiter splitters that track DIFFERENT enclosing state than the generic structuredFields.splitTopLevel: link-header._splitLinks tracks RFC 8288 `<uri-reference>` angle brackets AND quoted strings (a comma inside a URI must not split); safe-ical._splitUnquoted / safe-vcard._splitUnquoted track RFC 5545 / 6350 DQUOTE state with their own escaping. The shared shingle is the `for-loop + inQuote/escape state-machine + slice on the delimiter` idiom; the per-format enclosing rules (angle brackets vs none) are exactly why each can't call the shared splitter.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/mdoc.js:verifyIssuerSigned",
        "lib/network-dnssec.js:verifyRrset",
        "lib/tsa.js:verifyToken",
        "lib/vc.js:verify",
      ],
      reason: "v0.12.40 — signature-verify entry preamble shared by four credential / token / DNS verifiers: `validateOpts(allowedKeys) + mandatory algorithms-allowlist check + opts.at valid-Date guard + publicKey/keyResolver presence check`, then divergent domain logic. tsa.verifyToken verifies an RFC 3161 timestamp token (CMS SignedData + message-imprint + EKU); vc.verify verifies a W3C VC-JOSE-COSE credential (JWS/COSE + VCDM structural + validity window); mdoc.verifyIssuerSigned verifies an ISO 18013-5 mdoc (COSE_Sign1 IssuerAuth + MSO valueDigests matching); network-dnssec.verifyRrset verifies a DNSSEC RRSIG (RFC 4034 canonical RRset + RRSIG-prefix reconstruction). Each consumes a different wire format, returns a different shape, and throws a primitive-specific typed error — the shingle is the validate-then-guard preamble, not behaviour. Same family as the v0.12.33 cose.verify cluster.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/cose.js:_coseKeyBytes",
        "lib/cose.js:_bstr",
        "lib/mdoc.js:_bytes",
        "lib/network-dnssec.js:_bytes",
        "lib/network-dane.js:_bytes",
        "lib/privacy-pass.js:_bytes",
        "lib/content-digest.js:_bodyBytes",
        "lib/tsa.js:_bytes",
        "lib/eat.js:_toBuf",
        "lib/worm.js:_toBytes",
      ],
      reason: "v0.12.48 / v0.12.51 / v0.12.52 / v0.12.53 / v0.13.x — Buffer-coercion guard (`if (Buffer.isBuffer(x)) return x; if (x instanceof Uint8Array) return Buffer.from(x); ...`) repeats across byte-string-consuming primitives. The throw-on-unknown variants (cose / mdoc / dnssec / dane / tsa) each raise a MODULE-LOCAL typed error code naming the local argument; the JSON-fallback variants (eat._toBuf serializing a CBOR/EAT claims payload, worm._toBytes serializing a record to hash) instead JSON.stringify a non-bytes value. The duplicated prefix is the symptom; the cause is that JS can't throw a caller-namespaced ErrorClass (or choose the domain's serialization) without the local closure. Same documented exception as the v0.12.7 require-non-empty-string cluster — the per-domain error code / serialization is the divergence the dup detector can't see.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/cose.js:importKey",
        "lib/cose.js:exportKey",
        "lib/did.js:_jwkToKey",
        "lib/network-dnssec.js:_jwkKey",
      ],
      reason: "v0.13.20 — EC/OKP JWK-coordinate handling (`kty` + `crv` switch over P-256/P-384/P-521 + Ed25519, base64url x/y, `createPublicKey({ format: 'jwk' })`) is coincidentally similar across three unrelated wire formats: cose.importKey/exportKey map a COSE_Key (RFC 9052 §7 — INTEGER crv ids -1/-2/-3 and labels) to/from a KeyObject; did._jwkToKey resolves a W3C DID verification method's JWK; network-dnssec._jwkKey reconstructs a DNSKEY's public key. The curve identifiers, the surrounding map shape, and the direction (import builds a key from a map, export emits a map from a key) all differ per spec — extracting a shared helper would couple three independent standards on a syntactic accident. The shingle is the JWK-coordinate idiom, not behaviour; same documented exception as the v0.12.40 signature-verify-preamble cluster.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/dual-control.js:create",
        "lib/mdoc.js:verifyIssuerSigned",
        "lib/tsa.js:verifyToken",
      ],
      reason: "v0.12.40 — validateOpts-then-guard prelude shared between a create-style validator (dual-control.create builds a two-person-rule grant after validating its opts) and the timestamp / mdoc verifiers. The common shingle is the `validateOpts(allowedKeys) + chained guard + typed-error` idiom; the bodies diverge entirely (dual-control persists a control record; tsa/mdoc verify cryptographic structures). Same validate-then-guard family as the v0.12.29 / v0.12.33 clusters.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/cert.js:create",
        "lib/mail-send-deliver.js:deliver",
        "lib/vc.js:present",
      ],
      reason: "v0.12.42 — validateOpts-then-guard prelude shared by three builder-style functions: cert.create mints a certificate, mail-send-deliver.deliver sends a message, vc.present builds + signs a Verifiable Presentation. The common shingle is the `validateOpts(allowedKeys) + required-field / non-empty-array guards + typed-error throw` idiom; the bodies diverge entirely (X.509 minting / SMTP delivery / VC-JOSE-COSE presentation envelope). Same validate-then-guard family as the v0.12.29 / v0.12.33 / v0.12.40 clusters.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/eat.js:verify",
        "lib/auth/jar.js:parse",
        "lib/auth/status-list.js:fromJwt",
      ],
      reason: "v0.12.35 — token-verify delegation prelude: each validates an opts blob, delegates the signature/structure verification to a lower primitive, then applies its own post-checks + builds a typed result. eat.verify delegates to b.cwt.verify then enforces nonce / dbgstat / profile (RFC 9711); jar.parse delegates to b.auth.jwt.verifyExternal then enforces iss / client_id / anti-nesting (RFC 9101); status-list.fromJwt delegates to a JWS verify then reads the status-list bits. The shingle is the validate→delegate→post-check shape; each enforces a distinct spec's claims.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/archive-adapters.js:fs",
        "lib/archive-adapters.js:http",
        "lib/network-smtp-policy.js:mtaStsFetch",
        "lib/parsers/safe-env.js:readVar",
      ],
      reason: "v0.12.7 — `if (typeof <opt> !== \"string\" || <opt>.length === 0) throw new <Error>(...)` shape repeats across primitives validating REQUIRED string opts. validateOpts.requireNonEmptyString covers most call sites; the four flagged here are inline because they each carry a primitive-specific error CODE (adapter/bad-arg, smtp-policy/bad-arg, safe-env/bad-arg) that the helper's caller-error-class shape doesn't compose cleanly across — each primitive's typed-error class is module-local + the message string names the local opt. The duplicated shape is the symptom, not the cause; the cause is that JS doesn't have a way to throw an instance of caller-namespaced ErrorClass without the local closure.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/archive-read.js:extract",
        "lib/archive-tar-read.js:extract",
        "lib/auth/ciba.js:pollToken",
        "lib/auth/oid4vci.js:exchangePreAuthorizedCode",
        "lib/auth/oid4vci.js:issueCredential",
      ],
      reason: "v0.12.7 + v0.12.8 — `try { ... await ... } catch (e) { /* per-step cleanup */ throw e; }` shape repeats across primitives doing multi-step async work with per-step rollback. archive-read.extract + archive-tar.extract both clean up partial-extract files; ciba.pollToken cleans up rate-limit + retry state; oid4vci.exchange/issueCredential clean up partial credential-state. Each catch body is primitive-specific (the cleanup it does is the primitive's responsibility) — extraction would require a generic transaction-style helper which is itself a v1.0+ surface decision. Five-file repetition with primitive-specific cleanup bodies stays as the documented exception.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/archive-tar-read.js:_classifyTypeflag",
        "lib/archive-tar-read.js:inspect",
        "lib/auth/ciba.js:_registerInitialInterval",
        "lib/auth/oauth.js:exchangeToken",
        "lib/auth/oauth.js:pollDeviceCode",
        "lib/auth/oid4vci.js:createCredentialOffer",
        "lib/auth/oid4vci.js:exchangePreAuthorizedCode",
        "lib/restore-rollback.js:swap",
      ],
      reason: "v0.12.8 — Compact branching helpers (`if (x === A) return ...; if (x === B) return ...;` switch-style) repeat across primitives that map operator-supplied enum values to internal labels. archive-tar-read._classifyTypeflag maps single-char tar typeflags (0/1/2/3/4/5/6/7/x/g) to entry-type labels (file/symlink/hardlink/device/fifo/directory/etc.); archive-tar-read.inspect dispatches on the same typeflag set per-entry — distinct vocabulary from oauth.exchangeToken / oid4vci.createCredentialOffer / etc. which dispatch on grant_type / credential_format / step. The match is shape (chain of if-equals-return), not semantic. Extraction would require a generic enum-dispatch helper for trivially-different enums — that's an obscured abstraction. Each call site's enum + label set is primitive-specific.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/archive-read.js:_normalizeEntryTypePolicy",
        "lib/archive-tar-read.js:_normalizeEntryTypePolicy",
        "lib/archive.js:writeTo",
      ],
      reason: "v0.12.8 — `_normalizeEntryTypePolicy` shape is genuinely duplicated between archive-read.js + archive-tar-read.js — both copy DEFAULT_ENTRY_TYPE_POLICY and merge with operator opts. Could extract to a shared lib/_archive-policy.js helper in a future patch; for v0.12.8 keeping the duplication so the format-specific entry-type vocabulary (zip's external-attrs vs tar's typeflag) stays close to the reader that uses it. archive.js:writeTo is the unrelated third file in the dup cluster — its toBuffer + writeFileSync shape happens to share the 50-token shingle by coincidence (writeTo is the legacy ZIP write-to-path helper, not policy-related).",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/ai-disclosure.js:chatbot",
        "lib/backup/index.js:bundleAdapterStorage",
        "lib/importmap-integrity.js:build",
        "lib/metrics.js:shadowRegistry",
      ],
      reason: "v0.12.11/v0.12.12 — opts-validation cascade shape (chained `if (typeof opts.X !== \"...\") throw ...`) reaches 50-token duplication across primitives that each carry distinct semantic vocabulary. bundleAdapterStorage validates cryptoStrategy / recipient / passphrase / posture; importmap-integrity.build validates SRI hash list / nonce policy; metrics.shadowRegistry validates collector config; ai-disclosure.chatbot validates session / placement / jurisdiction per EU AI Act Art. 50(1). Extracting would require a generic options-cascade helper that loses per-primitive error codes operators grep for in audit logs.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/ai-disclosure.js:chatbot",
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
      ],
      reason: "v0.12.12 — `if (!opts || typeof opts !== \"object\") throw Error(...) ; if (typeof opts.X !== \"string\") throw Error(...)` argument-shape preamble is the framework's standard primitive boundary check. Every guard family member + every compliance / mail / auth primitive that takes an opts object shares this shingle. Extracting would require a generic argShape helper, but the throw-on-bad-shape carries primitive-specific Error subclasses (AiDisclosureError, GuardEnvelopeError, etc.) that operators grep for. Family is wide and stays inline by design.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/agent-idempotency.js:_checkArgs",
        "lib/agent-tenant.js:_sealField",
        "lib/atomic-file.js:copyDirRecursive",
        "lib/ddl-change-control.js:approve",
        "lib/ddl-change-control.js:reject",
        "lib/deprecate.js:alias",
        "lib/guard-filename.js:verifyExtractionPath",
        "lib/jose-jwe-experimental.js:decrypt",
        "lib/mail-deploy.js:_validateTlsRptReport",
        "lib/totp.js:uri",
      ],
      reason: "v0.12.7 — Generic string-argument validation shape: `if (typeof X !== \"string\" || X.length === 0) throw new <ErrorClass>(<code>, ...)` repeats across primitives validating REQUIRED non-empty string opts. Each call site emits a primitive-specific typed error class (BackupError, GuardFilenameError, IdempotencyError, AgentTenantError, AtomicFileError, DdlError, DeprecateError, JoseError, MailDeployError, TotpError) so extracting to a shared helper would lose the per-primitive error namespace. validateOpts.requireNonEmptyString covers most call sites where the caller's typed-error class composes with the helper's caller-error-class shape; the 9 file paths here are inline because each one's typed error has a primitive-local code namespace + message string the helper can't compose cleanly. Same shape as the v0.10.16 client-hints/csp/sandbox family-subset reason (inline for per-primitive typed errors). 5/9/3-file subsets at smaller token windows are the same family — one entry covers all of them.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/client-hints.js:acceptList",
        "lib/csp.js:build",
        "lib/mail-spam-score.js:_sanitizeReasons",
        "lib/router.js:_matchCompiled",
        "lib/sandbox.js:_validateAllowed",
        "lib/watcher.js:_compileIgnore",
      ],
      reason: "v0.10.16 — operator-supplied string-array opt iteration: each primitive walks a values[] list, performs per-element non-empty-string + CR/LF/NUL refusal, and emits a primitive-specific typed error (Client-Hints token / CSP source / spam reason / route pattern / sandbox allowlist / watcher ignore). Consolidating would lose the per-primitive error namespace and per-element semantic (e.g. CSP also refuses unsafe-* keywords; client-hints also refuses tokens with whitespace) — the iteration shape repeats but each body checks a different spec.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/oid4vp.js:_validateDcql",
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/auth/step-up.js:parseAuthorizationDetails",
        "lib/calendar.js:validate",
        "lib/fedcm.js:accountsResponse",
        "lib/fedcm.js:wellKnown",
        "lib/guard-saga-config.js:validate",
        "lib/network-heartbeat.js:_validateTarget",
        "lib/network-heartbeat.js:start",
        "lib/break-glass.js:_validatePolicySet",
        "lib/db.js:declareRequireDualControl",
        "lib/dsr.js:create",
        "lib/middleware/assetlinks.js:create",
      ],
      reason: "v0.10.16 — opts-object structural validation pattern: each primitive walks an operator-supplied opts/config object, asserts required-key presence with primitive-typed errors, and emits spec-named refusal codes. FedCM endpoints (W3C 2024), DCQL queries (OID4VP), AuthorizationDetails (RFC 9396), Assetlinks (Android), DualControl declarations, break-glass policy sets, DSR rights, sd-jwt-vc issuer, JSCalendar Event/Task/Note/Group (RFC 8984) — each enforces a distinct spec's required-field list. The repeating shingle is the boilerplate guard shape; consolidating couples unrelated spec namespaces.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/acme.js:listProfiles",
        "lib/hal.js:_normaliseLinks",
        "lib/hal.js:resource",
        "lib/mail-server-jmap.js:_resolveBackRefs",
        "lib/template.js:create",
        "lib/mail-auth.js:authResultsEmit",
        "lib/guard-mail-query.js:_walk",
        "lib/vault-aad.js:_canonicalize",
      ],
      reason: "v0.10.16 — tree-walker / link-collection helpers: each primitive walks an arbitrary nested structure (HAL _links normalization across string|object|array, JMAP back-reference resolution, ACME profile enumeration, template variable substitution, AuthResults header emission, mail-query AST walk, vault-AAD canonicalization). The shared shape is the `if (typeof x === 'string')` / `else if (Array.isArray(x))` / `else for-in object` dispatch; the bodies do entirely different semantic work per spec (RFC 4287 HAL / RFC 8620 JMAP / RFC 8555 ACME / Mustache-ish / RFC 8601 AuthResults).",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/content-digest.js:<top>",
        "lib/network-dane.js:<top>",
        "lib/tsa.js:<top>",
      ],
      reason: "v0.12.53 — identical framework require preamble + module-local typed-error declaration (`var nodeCrypto = require(\"node:crypto\"); var bCrypto = require(\"./crypto\"); var validateOpts = require(\"./validate-opts\"); var { defineClass } = require(\"./framework-error\"); var XError = defineClass(\"XError\", { alwaysPermanent: true });`). This is the standard top-of-file boilerplate for a crypto-touching primitive that throws a namespaced error; the only divergence is the error class name. Top-of-file requires are the project convention (rule §3), so the shared shape is unavoidable boilerplate, not extractable behaviour.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/asyncapi-bindings.js:<top>",
        "lib/lro.js:<top>",
        "lib/openapi-security.js:<top>",
      ],
      reason: "v0.10.16 — module-level constant table declarations (AsyncAPI binding type registry / google.rpc.Code map for LRO / OpenAPI security scheme types). The shared shape is `var X = Object.freeze({ k: v, ... });` populating a small lookup table; each table's keys are spec-specific (AsyncAPI bindings, gRPC code numbers 0-16, OAS security types).",
    },
    {
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
      reason: "v0.10.16 — state-machine transition / regex-prelude parse-then-build pattern: each primitive reads an operator-supplied string token (operation ID, transition state, decimal amount, ISO-8601 timestamp), asserts the shape via a small regex or enum, classifies a typed refusal code on miss, and emits / returns a structured value. DDL change-control approve/reject vs LRO cancel/status vs ISO-8601 parse vs money decimal-string parse share the `validate-shape-then-emit-typed-error` shape; the per-primitive vocabulary is spec-specific (DDL approval workflow / google.rpc LRO lifecycle / ISO-8601 grammar productions / ISO 4217 minor-unit decoding).",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/a2a.js:_validateCardShape",
        "lib/acme.js:buildCsr",
        "lib/guard-mail-move.js:validate",
      ],
      reason: "v0.11.22 — per-spec input-shape validation prelude: each primitive accepts an operator-supplied opts blob and walks a documented per-field shape check (A2A signed agent-card vs PKCS#10 CSR opts vs IMAP MOVE intent). The shingle similarity is the shared `if (typeof X !== 'string' || X.length === 0)` / `if (!Array.isArray(Y))` / per-field range checks; the bodies enforce entirely different spec contracts (W3C A2A card schema / RFC 2986 CSR opts / RFC 9051 IMAP MOVE).",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/guard-email.js:_detectAddressIssues",
        "lib/mail-server-jmap.js:eventSourceHandler",
        "lib/mail-server-jmap.js:downloadHandler",
        "lib/middleware/scim-server.js:_parseQuery",
      ],
      reason: "v0.11.29 + v0.11.30 — operator-supplied string-keyed parameter walk: each function iterates an external key=value source (RFC 5321 address-field components / RFC 8620 §7.3 SSE subscription opts / RFC 8620 §6.2 download URL query / RFC 7644 SCIM filter expression) and dispatches branch-per-key. Shared shape is the loop that splits → trims → conditionally maps each key into a different output domain. Consolidating would couple unrelated wire-format vocabularies.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/ai-model-manifest.js:build",
        "lib/calendar.js:validate",
        "lib/vex.js:statement",
      ],
      reason: "v0.11.31 — per-spec required-field assertion + typed-error pattern. Each primitive walks an operator-supplied document object, asserts the spec-mandated `@type` discriminator + required keys (`uid` / `componentId` / `vulnerability` / etc.), and throws a domain-typed FrameworkError with a `/<spec>/<violation>` code. CycloneDX 1.6 ML-BOM vs JSCalendar Event/Task vs OASIS CSAF 2.1 VEX statement — three different document schemas; consolidating the assert-prelude would couple unrelated spec vocabularies.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/a2a.js:_validateCardShape",
        "lib/calendar.js:validate",
        "lib/fedcm.js:wellKnown",
        "lib/middleware/assetlinks.js:create",
      ],
      reason: "v0.11.31 — opts-object shape validator pattern. Each primitive accepts a structured document (W3C A2A signed agent-card / JSCalendar Event/Task/Note/Group / Android Asset Links manifest / FedCM well-known manifest), walks the per-spec required keys, and throws a domain-typed error. The shared shingle is the per-field `typeof !== \"string\" || length === 0 || ...test(...)` chain; the per-spec vocabulary diverges entirely.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/importmap-integrity.js:build",
        "lib/mail-server-jmap.js:emailSubmissionSetHandler",
        "lib/middleware/security-headers.js:create",
      ],
      reason: "v0.11.38 — opts-object prelude that walks an operator-supplied map and validates each entry against a per-spec shape. Importmap-Integrity (W3C draft) walks `opts.modules`, JMAP EmailSubmission/set (RFC 8621 §7.5) walks `args.create`, security-headers walks `opts.headers`. Each entry's shape check is spec-distinct (SRI module shape vs JMAP EmailSubmission shape with envelope.mailFrom + envelope.rcptTo + identityId + emailId vs HTTP header-value sanitisation); only the `Object.keys + for-i loop + per-entry typeof guard` shell shingles.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/guard-mail-move.js:validate",
        "lib/guard-posture-chain.js:validate",
        "lib/mail-auth.js:arcEvaluate",
        "lib/mail-server-jmap.js:emailSubmissionSetHandler",
      ],
      reason: "v0.11.38 — per-spec validation walker pattern. Each primitive iterates an operator-supplied collection (IMAP MOVE intent / posture-set hop chain / ARC chain hops / JMAP EmailSubmission create/update/destroy maps) and emits a typed refusal per entry. RFC 9051 IMAP MOVE state-machine vs RFC 9.5 posture-chain ordering vs RFC 8617 ARC chain re-evaluation vs RFC 8621 §7.5 EmailSubmission shape — the shingle is the iterator + per-element error-shape construction; the body validations enforce four unrelated spec vocabularies.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/ddl-change-control.js:create",
        "lib/network.js:_setSocketKeepAlive",
        "lib/webhook.js:sign",
      ],
      reason: "v0.11.25 — typed-arg validation prelude across unrelated domains: DDL change-control opts validation, TCP socket keep-alive number-coercion, Stripe webhook sign opts validation. The shared shingle is the `if (typeof x !== \"number\" || !isFinite(x) || x < 0) throw new Error(...)` chain that every framework primitive runs at its boundary; each body then does something completely different (open a DDL ticket / set TCP_KEEPALIVE / HMAC-SHA-256 a Stripe signature).",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/agent-posture-chain.js:_union",
        "lib/compliance-ai-act.js:classify",
        "lib/mail-store.js:create",
        "lib/mail-store.js:search",
        "lib/mail-store.js:addMatch",
      ],
      reason: "v0.11.23 + v0.11.25 — accumulator-with-guards pattern: each function takes an operator-supplied scalar (id / category / filter-key) and selectively pushes a derived value into a shared collector after running a typed guard sequence. Posture-set union, EU AI Act classification, mail-store hardExpunge dedup, mail-store FTS search match-clause assembly — each enforces its own guard set + push-destination semantics. Consolidating would couple a posture domain, a regulatory classifier, a quota subtraction, and an FTS5 query builder.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/fsm.js:define",
        "lib/mail.js:_validateMessage",
      ],
      reason: "v0.11.25 — per-spec required-field validation prelude: each primitive consumes an operator-supplied definition/opts/message object and walks a sequence of `if (!x || typeof x !== '<type>') throw new <Primitive>Error(...)` shape-assertions naming the spec-specific code on each refusal. The shingle similarity is the shared validation-cascade idiom; the bodies enforce entirely different spec contracts (IETF SD-JWT-VC issuer opts vs flat-statechart `b.fsm` definition vs RFC 5322 mail message). Consolidating would couple the SD-JWT issuer's audience/key-binding lifecycle, the FSM's state/transition-shape contract, and the mail submitter's address/CRLF/MIME rules — each error namespace is the spec's own.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/audit-daily-review.js:create",
        "lib/auth/saml.js:create",
        "lib/auth/oid4vci.js:create",
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/cloud-events.js:wrap",
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/daemon.js:_validateStartOpts",
        "lib/daemon.js:_validateStopOpts",
        "lib/data-act.js:shareWithThirdParty",
        "lib/ddl-change-control.js:create",
        "lib/external-db-migrate.js:create",
        "lib/fda-21cfr11.js:posture",
        "lib/fda-21cfr11.js:_validateSignatureInput",
        "lib/fdx.js:consentReceipt",
        "lib/file-upload.js:_validateCreateOpts",
        "lib/http-client-cache.js:create",
        "lib/http-client.js:_validateDownloadOpts",
        "lib/inbox.js:create",
        "lib/mcp-tool-registry.js:verifyCall",
        "lib/middleware/db-role-for.js:create",
        "lib/middleware/dpop.js:create",
        "lib/middleware/no-cache.js:create",
        "lib/middleware/span-http-server.js:create",
        "lib/middleware/tus-upload.js:create",
        "lib/outbox.js:create",
        "lib/redact.js:installOutboundDlp",
        "lib/sec-cyber.js:eightKArtifact",
        "lib/self-update.js:_validateVerifyOpts",
        "lib/static.js:_validateCreateOpts",
        "lib/vault/seal-pem-file.js:sealPemFile",
        "lib/vex.js:document",
        "lib/watcher.js:_validateOpts",
        "lib/web-push-vapid.js:buildVapidAuthHeader",
      ],
      reason: "v0.10.16 — factory-primitive validateOpts prelude across heterogeneous RFC/spec primitives: each create()/_validateXOpts wraps `validateOpts.requireObject + validateOpts(allowedKeys) + per-spec required-field assertions + typed-error throw + closure-captured return`. The shingle similarity is the shared opts-validation idiom; each primitive enforces a distinct spec's required-field list (OASIS CSAF VEX / RFC 8693 token exchange / SEC Cyber 8-K / FDA 21 CFR Part 11 e-signature / NIST 800-218 SSDF self-update / W3C SafeBrowsing redaction / RFC 9728 Protected Resource Metadata / WebPush VAPID JWT signer / etc.). Consolidating would couple unrelated spec namespaces — every primitive's error code names the spec it enforces.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/agent-snapshot.js:_runHandler",
        "lib/agent-tenant.js:_checkDestroyPreconditions",
        "lib/auth/dpop.js:verify",
        "lib/auth/dpop.js:buildProof",
        "lib/auth/fido-mds3.js:_parseJws",
        "lib/auth/fido-mds3.js:_verifyJws",
        "lib/auth/jwt.js:decode",
        "lib/auth/jwt.js:verify",
        "lib/auth/jwt-external.js:verifyExternal",
        "lib/auth/jwt-external.js:_fetchJwks",
        "lib/auth/oauth.js:verifyBackchannelLogoutToken",
        "lib/auth/oauth.js:verifyIdToken",
        "lib/auth/oauth.js:exchangeToken",
        "lib/auth/oauth.js:nativeSsoExchange",
        "lib/auth/oauth.js:pollDeviceCode",
        "lib/auth/oid4vci.js:_verifyProofJwt",
        "lib/auth/oid4vci.js:createCredentialOffer",
        "lib/auth/oid4vci.js:exchangePreAuthorizedCode",
        "lib/auth/openid-federation.js:parseEntityStatement",
        "lib/auth/openid-federation.js:verifyEntityStatement",
        "lib/auth/saml.js:_verifyEmbeddedXmlDsig",
        "lib/auth/saml.js:verifyResponse",
        "lib/auth/saml.js:parseLogoutRequest",
        "lib/auth/saml.js:parseLogoutResponse",
        "lib/auth/sd-jwt-vc-holder.js:store",
        "lib/auth/step-up.js:parseAuthorizationDetails",
        "lib/auth/oid4vp.js:_validateDcql",
        "lib/auth/ciba.js:_registerInitialInterval",
        "lib/backup/index.js:scheduleTest",
        "lib/dsr.js:submit",
        "lib/fedcm.js:accountsResponse",
        "lib/guard-saga-config.js:validate",
        "lib/guard-snapshot-envelope.js:validate",
        "lib/incident-report.js:open",
        "lib/jose-jwe-experimental.js:decrypt",
        "lib/mail-crypto-smime.js:verify",
        "lib/mail-crypto-smime.js:_verifySignerInfo",
        "lib/mail-greylist.js:check",
        "lib/mail-helo.js:evaluate",
        "lib/network-heartbeat.js:_validateTarget",
        "lib/network-smtp-policy.js:tlsRptParseReport",
        "lib/restore-rollback.js:swap",
        "lib/restore-rollback.js:rollback",
        "lib/self-update.js:poll",
        "lib/self-update.js:verify",
      ],
      reason: "v0.10.16 — JOSE / signature-verify / posture-check prelude across heterogeneous primitives: each verify/check pattern decomposes a token / envelope / posture set, asserts spec-required shape (header.alg in allowlist / kty in allowlist / iss CT-compare / aud match / time-window), and dispatches per-alg via shared helpers. The shingle similarity is the boilerplate header-parse + alg-allowlist + timing-safe compare; each primitive enforces a distinct spec (RFC 7519 JWT / RFC 7515 JWS / RFC 9449 DPoP / OASIS CSAF VEX / FIDO MDS / SAML 2.0 / RFC 9528 SD-JWT / W3C FedCM 2024 / RFC 8917 backchannel-logout / SBOM compliance / OIDC Federation / OID4VCI / CIBA / RFC 8460 TLS-RPT / restore-rollback). Consolidating would lose per-spec error code namespacing.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/a2a.js:createCard",
        "lib/a2a.js:verifyCard",
        "lib/asyncapi-bindings.js:kafka",
        "lib/asyncapi.js:_addChannel",
        "lib/asyncapi.js:_normaliseMessage",
        "lib/mail.js:resendTransport",
        "lib/middleware/protected-resource-metadata.js:create",
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/web-push-vapid.js:buildVapidAuthHeader",
      ],
      reason: "v0.10.16 — registry/manifest emitter pattern: each primitive emits a structured artifact (A2A agent card, AsyncAPI channel/message manifest, mail transport descriptor, RFC 9728 protected-resource metadata, sanctions-list fetcher config, VAPID JWT header) by combining operator-supplied identity fields with auto-derived shape defaults. Each output conforms to a distinct spec (Google A2A / AsyncAPI 3.0 / nodemailer-compatible transport / RFC 9728 PR-Metadata / OFAC SDN feed / RFC 8292 VAPID).",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/agent-tenant.js:_checkDestroyPreconditions",
        "lib/auth/dpop.js:verify",
        "lib/auth/dpop.js:buildProof",
        "lib/auth/oauth.js:nativeSsoExchange",
        "lib/auth/oauth.js:exchangeToken",
        "lib/auth/oauth.js:verifyIdToken",
        "lib/auth/oauth.js:pollDeviceCode",
        "lib/auth/ciba.js:_registerInitialInterval",
        "lib/auth/fido-mds3.js:_parseJws",
        "lib/auth/fido-mds3.js:_verifyJws",
        "lib/auth/jwt-external.js:verifyExternal",
        "lib/auth/jwt.js:decode",
        "lib/auth/oid4vci.js:_verifyProofJwt",
        "lib/auth/oid4vci.js:createCredentialOffer",
        "lib/auth/oid4vci.js:exchangePreAuthorizedCode",
        "lib/auth/openid-federation.js:parseEntityStatement",
        "lib/auth/oid4vp.js:_validateDcql",
        "lib/backup/index.js:scheduleTest",
        "lib/break-glass.js:_validatePolicySet",
        "lib/cms-codec.js:encodeEnvelopedData",
        "lib/cms-codec.js:encodeSignedData",
        "lib/ddl-change-control.js:propose",
        "lib/mail-crypto-pgp.js:experimentalEncrypt",
        "lib/mail-helo.js:evaluate",
        "lib/restore-rollback.js:swap",
      ],
      reason: "v0.10.16 — token/proof/structure verification + pre-condition assertion across heterogeneous primitives: each verifies an operator-supplied artifact (DPoP proof / JWT / FIDO MDS JWS / OID4VCI proof / CIBA registration / OIDC federation entity statement / OID4VP DCQL query / CMS SignedData/EnvelopedData / break-glass policy set / DDL change-control proposal / restore-rollback swap / mail HELO etc.) by parsing the header, asserting alg/kty allowlist, decoding the payload, and dispatching per-spec validation. The shingle similarity is the parse-header → alg-allowlist → decode-payload idiom; each call site enforces a distinct spec (RFC 9449 DPoP / RFC 7519 JWT / FIDO MDS / OID4VCI / CIBA / OIDC Federation / DCQL / RFC 5652 CMS / break-glass policy / DDL workflow / RFC 5321 SMTP HELO).",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/agent-idempotency.js:_checkArgs",
        "lib/agent-tenant.js:_sealField",
        "lib/atomic-file.js:copyDirRecursive",
        "lib/ddl-change-control.js:approve",
        "lib/ddl-change-control.js:reject",
        "lib/deprecate.js:alias",
        "lib/jose-jwe-experimental.js:decrypt",
        "lib/mail-deploy.js:_validateTlsRptReport",
        "lib/mail-deploy.js:parseTlsRptReport",
        "lib/mail-deploy.js:tlsRptIngestHttp",
        "lib/mail-deploy.js:mtaStsPublish",
        "lib/totp.js:uri",
      ],
      reason: "v0.10.15 — defensive RFC-specific opts-validation + typed-error throw shape across heterogeneous primitives. Each call site validates a different RFC spec's required fields (RFC 8460 TLS-RPT §4.4 / RFC 8461 MTA-STS / RFC 6238 TOTP / RFC 5280 X.509 / JOSE) with a primitive-specific typed error class. Consolidating would couple unrelated spec namespaces — every primitive's error code names the spec it enforces. The shingle similarity is the boilerplate `typeof x !== \"string\" || x.length === 0` shape, not behaviour.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/http-client.js:_reject",
        "lib/mail-deploy.js:tlsRptIngestHttp",
        "lib/mail-deploy.js:_collectAndProcess",
        "lib/middleware/body-parser.js:_bufferBody",
      ],
      reason: "v0.10.15 — request-body collection / rejection shape (req.on('data', ...) + safeBuffer.boundedChunkCollector + cap-overflow handling). Each call site implements RFC-specific 4xx semantics (httpClient: outbound timeout / size; mail-deploy: RFC 8460 §5.4 TLS-RPT ingest; body-parser: framework-wide inbound body cap). The duplicated shingle is the bounded-collect pattern from safeBuffer; consolidating into a single helper would force every collector into a single error-code namespace and lose the RFC-specific status-code mapping (413 vs 415 vs custom).",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/mail-deploy.js:parseTlsRptReport",
        "lib/mail-server-imap.js:create",
        "lib/mail-server-pop3.js:create",
      ],
      reason: "v0.10.15 — opts-arg defensive entry-validation shape (opts = opts || {}; typeof checks + buffer/string coercion + bounded-input refusal). mail-deploy.parseTlsRptReport validates inbound RFC 8460 reports; mail-server-imap.create + mail-server-pop3.create validate IMAP4rev2 / POP3 listener opts. Each owns a primitive-specific error class (TlsRptParseError / MailServerImapError / MailServerPop3Error) and refuses on RFC-specific fields. Consolidating would couple wire-protocol listener init with one-shot report parsing.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/mail-crypto-pgp.js:_padTo32",
        "lib/mail-crypto-smime.js:checkCert",
        "lib/mail-deploy.js:tlsRptIngestHttp",
        "lib/mail-deploy.js:_collectAndProcess",
      ],
      reason: "v0.10.15 — defensive typeof / instanceof / Buffer.isBuffer + typed-error throw boilerplate spanning three different mail-side primitives. _padTo32 enforces a 32-byte buffer invariant for OpenPGP packet padding; checkCert validates X.509 PEM cert shape per RFC 5280; tlsRptIngestHttp validates RFC 8460 §5.4 HTTP request shape. Each owns a distinct error class and validates a primitive-specific input format. Consolidation would couple OpenPGP packet semantics with S/MIME cert handling with HTTP handler dispatch.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/oauth.js:deviceAuthorization",
        "lib/auth/oauth.js:parseCallback",
        "lib/ddl-change-control.js:_hashSql",
        "lib/mail-rbl.js:query",
      ],
      reason: "Defensive opts-object validation shape (typeof check + length / regex / range guard + RFC-specific typed-error throw) appears across RFC 8628 device authorization, OAuth callback parsing, DDL change-control SQL hashing, and DNSBL query parameter validation. Each error class belongs to its own RFC namespace and the validated fields are domain-specific (device_code vs SQL statement vs DNSBL hostname); consolidation would couple unrelated specs.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/agent-snapshot.js:_runHandler",
        "lib/dsr.js:submit",
        "lib/self-update.js:poll",
      ],
      reason: "Async-handler invocation shape — try/catch wrapper around a user-supplied callback that emits a typed audit event on failure and surfaces a domain-specific error class. agent-snapshot drains in-flight envelopes, dsr.submit runs operator request handlers under retention posture, self-update.poll runs the operator release-URL fetch. Each owns a distinct audit namespace and error class; consolidation would couple snapshot drain semantics with DSR retention and self-update polling.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/guard-email.js:_detectAddressIssues",
        "lib/middleware/scim-server.js:_parseQuery",
      ],
      reason: "Three unrelated string-parser primitives that incidentally share a 50-token charCodeAt-driven scan shingle. _detectAddressIssues walks RFC 5322 addr-spec bytes; _parseQuery walks SCIM filter tokens (RFC 7644 §3.4.2.2); _splitSemver walks SemVer 2.0.0 §2 version-core + pre-release + build identifiers. Each owns a domain-specific error class. Consolidation would couple RFC 5322 / RFC 7644 / SemVer parsing into one primitive none of them want.",
    },
    {
      files: [
        "lib/auth/dpop.js:verify",
        "lib/auth/jwt.js:_requireNumericDate",
        "lib/auth/oauth.js:verifyBackchannelLogoutToken",
      ],
      reason: "Distinct RFC primitives (RFC 9449 DPoP / RFC 7519 JWT / OIDC Back-Channel Logout) that share a `replayStore.checkAndInsert(jti, expireAtMs)` + numeric-date-bound shingle. Each uses its own typed error class (auth-dpop / auth-jwt / auth-oauth namespaces) with file-specific code and field tuple. Consolidation would couple three spec-defined verification primitives.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/agent-idempotency.js:<top>",
        "lib/agent-snapshot.js:<top>",
        "lib/guard-dsn.js:<top>",
        "lib/guard-imap-command.js:<top>",
        "lib/guard-jmap.js:<top>",
        "lib/guard-list-id.js:<top>",
        "lib/guard-list-unsubscribe.js:<top>",
        "lib/guard-mail-compose.js:<top>",
        "lib/guard-mail-move.js:<top>",
        "lib/guard-mail-query.js:<top>",
        "lib/guard-mail-reply.js:<top>",
        "lib/guard-mail-sieve.js:<top>",
        "lib/guard-message-id.js:<top>",
        "lib/guard-posture-chain.js:<top>",
        "lib/guard-smtp-command.js:<top>",
        "lib/guard-stream-args.js:<top>",
        "lib/mail-greylist.js:<top>",
        "lib/guard-pop3-command.js:<top>",
        "lib/mail-server-imap.js:<top>",
        "lib/mail-server-jmap.js:<top>",
        "lib/mail-server-mx.js:<top>",
        "lib/mail-server-pop3.js:<top>",
        "lib/mail-server-submission.js:<top>",
        "lib/mail-server-registry.js:<top>",
        "lib/money.js:<top>",
        "lib/asn1-der.js:<top>",
        "lib/safe-sieve.js:<top>",
        "lib/network-dns-resolver.js:<top>",
      ],
      reason: "Top-of-file JSDoc + module banner block — each module ships an @module / @nav / @title / @intro / @card scaffold per the wiki source-driven convention (the wiki pages are auto-derived from these blocks at boot). The shingle similarity is the banner shape, not behaviour. Removing or consolidating the banners would break the wiki auto-derivation.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/guard-dsn.js:_checkControlChars",
        "lib/guard-imap-command.js:validate",
        "lib/guard-list-id.js:_hasControlChar",
        "lib/guard-list-unsubscribe.js:_hasControlChar",
        "lib/guard-pop3-command.js:validate",
      ],
      reason: "charCodeAt-loop control-byte scan (refuse C0 / DEL / NUL / bare-LF / bare-CR). Each primitive runs the scan on a structurally different payload (DSN report body / IMAP command line / List-ID header / List-Unsubscribe header) and surfaces a primitive-specific typed error; consolidating would couple four unrelated wire formats. Mirrors the same charCodeAt-loop pattern that lib/codepoint-class.js owns for the guard-html / guard-svg / guard-csv family, but the protocols handled here use ASCII-only profiles where the codepointClass machinery would be over-kill.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/api-key.js:_validateIssueOpts",
        "lib/http-client-cache.js:create",
        "lib/http-client.js:_validateDownloadOpts",
        "lib/mail-server-tls.js:context",
        "lib/self-update.js:_validateVerifyOpts",
        "lib/watcher.js:_validateOpts",
      ],
      reason: "Generic opt-validation entry — validateOpts.requireObject + a cascade of requireNonEmptyString / requireFiniteNumber / etc. calls. Every operator-facing primitive's create()/issue()/verify() entry opens this way: entry-point opts THROW on bad input (operator catches typo at boot), distinct from drop-silent observability sinks and default-on-missing request-shape readers. Tokens collide because validateOpts is the single source of truth for opt-validation shape; that's the point of having it. Each call site validates structurally different opt-shapes — consolidation would couple unrelated primitives.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/data-act.js:recordSwitchRequest",
        "lib/mail-server-tls.js:context",
        "lib/watcher.js:_validateOpts",
      ],
      reason: "Three distinct primitives sharing a fs-stat + mtime-mtimeMs change-detection idiom. b.dataAct.recordSwitchRequest reads an event log; b.mail.server.tls.context detects cert rotation; b.watcher polls files. Each surfaces a different signal (DSR audit / TLS reload / fs.watch fallback) on a different operator-supplied path — consolidating into a 'fileChangeDetector' primitive would couple three unrelated lifecycles.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/daemon.js:_readPidFile",
        "lib/daemon.js:_validateStartOpts",
        "lib/data-act.js:declareProduct",
        "lib/data-act.js:shareWithThirdParty",
        "lib/mail-dkim.js:_merge",
        "lib/mail-dkim.js:bootstrap",
        "lib/mail-dkim.js:dualSigner",
        "lib/mail-mdn.js:_generateBoundary",
        "lib/mail-mdn.js:build",
        "lib/self-update.js:poll",
        "lib/watcher.js:_detectAutoMode",
      ],
      reason: "Generic JS lambda + object-assign + closure boilerplate. Any subset of these unrelated primitives (daemon PID-file read, data-act DSR third-party share / EU Data Act product declaration, dkim dualSigner merge / bootstrap keypair mint, MDN boundary / opt validation / report build, self-update release polling, watcher fs.watch mode detection) can cluster via the 50-token shingle. Distinct domains: process lifecycle / privacy compliance / mail crypto / mail DSN / framework self-update / fs watching. The shared shape is structural boilerplate, not behavior.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/fido-mds3.js:_parseJws",
        "lib/auth/jwt.js:decode",
        "lib/auth/oauth.js:verifyBackchannelLogoutToken",
        "lib/jose-jwe-experimental.js:decrypt",
      ],
      reason: "JOSE compact-serialization decode shape — base64url decode of header + structured parse + alg/type assertions. Each primitive owns its own compact-form contract (FIDO MDS3 attestation, JWT verify, OIDC back-channel logout-token verify, experimental JWE decrypt); merging would couple four spec-defined verification routines with distinct field sets.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/agent-idempotency.js:_checkArgs",
        "lib/agent-tenant.js:_sealField",
        "lib/atomic-file.js:copyDirRecursive",
        "lib/ddl-change-control.js:approve",
        "lib/ddl-change-control.js:reject",
        "lib/deprecate.js:alias",
        "lib/jose-jwe-experimental.js:decrypt",
        "lib/totp.js:uri",
      ],
      reason: "Generic JS object-construction + buffer-coercion + typed-error throw shape. Eight unrelated primitives (agent idempotency arg check, per-tenant cryptoField seal, atomic-file recursive copy, DDL approve/reject, deprecate alias plumbing, experimental JWE compact-form header decode, TOTP URI builder) share the 50-token inline-validation shingle — each owns a distinct error class and validates a structurally different object. Extracting would couple eight domains.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/metrics.js:_shadowSetOf",
        "lib/middleware/require-methods.js:create",
        "lib/middleware/security-txt.js:_arrayOfStrings",
        "lib/ws-client.js:connect",
      ],
      reason: "Generic array-of-non-empty-strings validator shape — typeof+length+typeof+length per-item walk. Each domain validates a structurally different array (metrics counter / gauge / info name lists; HTTP method allowlist; security.txt Contact lines; WebSocket protocol list). Extracting would force these four call sites onto one error class + one option key per validate signature; the inline shape stays per-domain typed.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/daemon.js:_safeAuditEmit",
        "lib/mail-server-imap.js:_emit",
        "lib/mail-server-imap.js:create",
        "lib/mail-server-imap.js:listen",
        "lib/mail-server-jmap.js:_emit",
        "lib/mail-server-jmap.js:create",
        "lib/mail-server-mx.js:_emit",
        "lib/mail-server-mx.js:_validateDomainHardened",
        "lib/mail-server-mx.js:create",
        "lib/mail-server-mx.js:listen",
        "lib/mail-server-pop3.js:_emit",
        "lib/mail-server-pop3.js:_assertTenantOrRefuse",
        "lib/mail-sieve.js:_emit",
        "lib/mail-server-pop3.js:create",
        "lib/mail-server-pop3.js:listen",
        "lib/mail-dav.js:_emit",
        "lib/mail-server-managesieve.js:_emit",
        "lib/mail-server-managesieve.js:create",
        "lib/mail-server-managesieve.js:listen",
        "lib/mail-server-submission.js:_emit",
        "lib/mail-server-submission.js:_validateDomainHardened",
        "lib/mail-server-submission.js:create",
        "lib/mail-server-submission.js:listen",
        "lib/mail.js:create",
        "lib/observability-otlp-exporter.js:create",
        "lib/self-update.js:_safeAuditEmit",
        "lib/self-update.js:<top>",
      ],
      reason: "Per-module audit-emit wrapper + the matching `_validateDomainHardened(d, label)` wrapper around `b.guardDomain.validate(...)` + the listener `create(opts)` opt-normalization shell. Each module's audit calls land on a distinct action-namespace (daemon.* / mail.server.mx.* / mail.server.submission.* / self-update.*); the domain validators wrap the SAME b.guardDomain.validate but emit to different audit events; the listener create() entries normalize structurally-different opt shapes. Mirrors the audit-emit-wrapper pattern that lib/agent-audit.js extracted for the agent-substrate modules.",
    },
    {
      files: [
        "lib/mail-server-mx.js:create",
        "lib/mail-server-submission.js:create",
        "lib/self-update.js:<top>",
      ],
      reason: "MX listener + submission listener share the SMTP connection-lifecycle scaffold (bind / accept / per-connection state init / idle-timer / wire-protocol read loop) because they implement the same RFC 5321 wire protocol with different verb-set + AUTH semantics. The shared scaffold is a known refactoring target — see `b-mail-server-submission-spec.md` §'Composition contract' for the planned `lib/_mail-server-base.js` extraction. Allowlisted with documented intent because (1) the listener-specific verb dispatch + state transitions diverge enough that a v1 base module would carry too many overrideable hooks to be cleaner than the current shape, and (2) further mail-stack listeners (IMAP / JMAP) will inform what the right base abstraction looks like before factoring. self-update's <top> banner shape happens to match the SMTP-listener create() shingle by coincidence — its module is unrelated.",
    },
    {
      files: [
        "lib/mail-server-mx.js:create",
        "lib/mail-server-submission.js:create",
        "lib/observability-otlp-exporter.js:create",
      ],
      reason: "Same shared SMTP listener create() shingle as the entry above; observability-otlp-exporter create() coincidentally shares the bind + listen + connection-tracker pattern (it accepts inbound OTLP spans on a TCP socket). All three carry distinct domain-specific opts validation + protocol logic.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/mail-server-imap.js:_handleConnection",
        "lib/mail-server-mx.js:_handleConnection",
        "lib/mail-server-pop3.js:_handleConnection",
        "lib/mail-server-submission.js:_handleConnection",
        "lib/mail-server-imap.js:listen",
        "lib/mail-server-mx.js:listen",
        "lib/mail-server-pop3.js:listen",
        "lib/mail-server-submission.js:listen",
        "lib/mail-server-imap.js:create",
        "lib/mail-server-pop3.js:create",
      ],
      reason: "Mail-listener connection-lifecycle scaffold — `_handleConnection(socket)` + `listen(opts)` + `create(opts)` share the bind / per-connection-state-init / idle-timer / wire-protocol read-loop shape because all four listeners run the same Node net.createServer scaffold under different RFC verb sets (RFC 5321 MX, RFC 6409 submission, RFC 9051 IMAP, RFC 1939 POP3). Same documented refactoring target as the SMTP-create() entry above — the planned `lib/_mail-server-base.js` extraction (per `b-mail-server-submission-spec.md`) will fold these once the verb-dispatch divergence settles after JMAP / WebPush / Sieve land. Listener-specific verb dispatch + state transitions diverge enough today that a v1 base module would carry too many overrideable hooks to be cleaner than the current shape.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/mail-server-imap.js:_handleAuthenticate",
        "lib/mail-server-mx.js:_handleRcptTo",
        "lib/mail-server-submission.js:_handleAuth",
      ],
      reason: "Per-IP rate-limit admit-check + transient-refusal + close shape — `rateLimit.checkAuthAdmit` / `checkRcptAdmit` returning ok=false leads to the same audit-emit + 421/[ALERT] reply + close-connection trio across mail-server-{imap,mx,submission}. IMAP's _handleAuthenticate gates AUTHENTICATE against AUTH-failure budget; MX's _handleRcptTo gates RCPT TO against RCPT-failure budget (RFC 5321 §3.5 enumeration); submission's _handleAuth gates AUTH against the AUTH-failure budget. Three different verb-dispatch contexts emitting three distinct audit actions on three different listeners — consolidating would couple unrelated RFC verb-set policies into one wrapper.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/guard-imap-command.js:validate",
        "lib/guard-jmap.js:validate",
        "lib/guard-mail-query.js:_walk",
        "lib/guard-pop3-command.js:validate",
        "lib/guard-smtp-command.js:validate",
      ],
      reason: "Mail-protocol guard.validate() wire-shape — every wire-protocol guard (RFC 5321 SMTP, RFC 9051 IMAP, RFC 1939 POP3, RFC 8620 JMAP) plus the JMAP/IMAP query AST walker shares an opts-shape resolver + control-byte scan + verb-dispatch / node-dispatch frame. Each emits a primitive-specific typed error tuple against a different wire grammar — extracting would couple four independent RFC grammars under one ambiguous interface. The shared substrate (`b.gateContract.resolveProfileAndPosture` + the `lib/codepoint-class.js` scanners) is already the right abstraction.",
    },
    {
      files: [
        "lib/acme.js:listProfiles",
        "lib/mail-server-jmap.js:_resolveBackRefs",
        "lib/template.js:create",
      ],
      reason: "Three structurally-unrelated primitives — ACME ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)) profile enumeration, JMAP back-reference resolution ([RFC 8620 §3.7](https://www.rfc-editor.org/rfc/rfc8620#section-3.7)), and template engine create — sharing an `Object.keys(...)` + per-key copy + return-object shingle. Each operates on a different domain (CA profile descriptors / JMAP result store / template helper registry) with primitive-specific validation; consolidating would couple three independent specs.",
    },
    {
      files: [
        "lib/break-glass.js:_validatePolicySet",
        "lib/external-db.js:assertRoleHardening",
        "lib/mail-deploy.js:mtaStsPublish",
      ],
      reason: "Three structurally-unrelated primitives — break-glass policy validation, external-db role-hardening assertion, mail-deploy MTA-STS policy publish — share a `validateOpts.requireObject` + per-field type-check + `Array.isArray` length-cap cascade. Each validates its own domain-specific opts shape; consolidating would couple privacy / DB / mail-protocol opt vocabularies under one ambiguous validator.",
    },
    {
      files: [
        "lib/backup/manifest.js:_canonical",
        "lib/legal-hold.js:list",
        "lib/mail-journal.js:list",
      ],
      reason: "Three structurally-unrelated primitives — backup manifest canonicalization, legal-hold record list, mail-journal record list — share an `Array.map` + per-row destructure + return-object shape. Each operates on a different domain (backup manifest entries / legal-hold rows / journaled mail entries) with primitive-specific column schemas; consolidating would couple three unrelated DB-row → API-object mappers.",
    },
    {
      files: [
        "lib/cra-report.js:conformityAssessment",
        "lib/mail-agent.js:consumer",
        "lib/mail-journal.js:create",
      ],
      reason: "Three structurally-unrelated primitives — CRA Article 13 conformity-assessment scaffolding, mail-agent queue consumer factory, mail-journal create() — share a `validateOpts.requireObject` + per-field type-check cascade with shared opt-name vocabulary (`audit` / `vault` / `db`). Each validates its own domain-specific opts shape (CRA = product/conformity metadata; mail-agent = consumer wiring; mail-journal = WORM storage handle); consolidating would couple compliance / agent-substrate / journal opt vocabularies under one ambiguous validator.",
    },
    {
      files: [
        "lib/guard-cidr.js:compliancePosture",
        "lib/guard-domain.js:compliancePosture",
        "lib/guard-jsonpath.js:compliancePosture",
        "lib/guard-mime.js:compliancePosture",
        "lib/guard-regex.js:compliancePosture",
        "lib/guard-shell.js:compliancePosture",
        "lib/guard-smtp-command.js:detectBodySmuggling",
        "lib/guard-template.js:compliancePosture",
        "lib/guard-time.js:compliancePosture",
        "lib/guard-uuid.js:compliancePosture",
      ],
      reason: "Standalone-guard compliancePosture entry-points + the SMTP smuggling-detector all share a small-body validate-input-then-loop-with-byte-check token pattern. Surfaced after v0.9.46 extracted detectBodySmuggling from the MX listener inline copy into guard-smtp-command per the modular safe/guard discipline. Distinct primitives — each emits its own posture verdict or threat boolean.",
    },
    {
      files: [
        "lib/guard-list-id.js:_refuse",
        "lib/guard-list-unsubscribe.js:_verdict",
        "lib/guard-smtp-command.js:_parseAuthCommandSyntax",
        "lib/safe-dns.js:_decodeOpt",
      ],
      reason: "Four distinct domain primitives (RFC 2919 list-id refusal, RFC 2369/8058 list-unsubscribe verdict, RFC 4954 SMTP AUTH command parser, RFC 6891 EDNS0 option decoder) that share a small-result-shape constructor + range-bounded byte access pattern. Each emits its own typed error/result tuple — consolidation would couple a list-validator, an SMTP command parser, and a DNS opt-record decoder. Surfaced after the guard-smtp-command rename in PR #72 brought the AUTH-command parser into the cluster.",
    },
    {
      files: [
        "lib/auth/jwt.js:_b64urlEncode",
        "lib/auth/oauth.js:_b64urlEncode",
        "lib/pagination.js:_b64urlEncode",
      ],
      reason: "Three call-site wrappers around b.crypto.toBase64Url/fromBase64Url that each carry a distinct typed error (AuthError for jwt + oauth, PaginationError for pagination) on the type-guard branch. The shared shape is `if (typeof s !== 'string') throw <DomainError>; return bCrypto.fromBase64Url(s);` — extracting further would couple the auth-error namespace with the pagination-error namespace. The framework's b.crypto.toBase64Url/fromBase64Url is the actual extracted primitive these wrappers consume.",
    },
    {
      files: [
        "lib/cloud-events.js:parse",
        "lib/pick.js:_pickInner",
        "lib/problem-details.js:create",
      ],
      reason: "Object.keys(...) iteration + POISONED_KEYS allowlist + per-key copy into output. Each call site preserves its own per-field semantics (CloudEvents pulls extensionContext per spec, pick implements the operator-supplied projection, problem-details applies RFC 9457 §3 reserved-field rules) — extracting would couple unrelated specs. pick.POISONED_KEYS is the shared substrate constant, already imported.",
    },
    {
      files: [
        "lib/a2a-tasks.js:_readBody",
        "lib/keychain.js:_drain",
        "lib/middleware/tus-upload.js:_readChunk",
      ],
      reason: "req.on('data'/'end'/'error') promise wrapper + safeBuffer.boundedChunkCollector cap-bounded streaming-body collector. Each call site bounds at the per-domain cap (A2A 1 MiB, tus-upload per-chunk cap, keychain per-operation cap) and surfaces a domain-specific error class on cap overflow — extracting would couple unrelated wire formats into a single primitive that none of them want.",
    },
    {
      mode: "family-subset",
      files: [
        "lib/auth/step-up.js:_quote",
        "lib/cdn-cache-control.js:parse",
        "lib/client-hints.js:_scanControlBytes",
        "lib/mail-require-tls.js:parseTlsRequiredHeader",
        "lib/middleware/bearer-auth.js:create",
        // v0.9.19 — guardMessageId's RFC 5322 §3.6.4 validator runs
        // the same charCodeAt + (c < 0x20 || c === 0x7F) scan.
        "lib/guard-message-id.js:validate",
        // v0.9.20 — guardMail* family adds folder-name / sieve-name /
        // header-value / scalar-string scans of the same shape.
        "lib/guard-mail-compose.js:_checkHeaderValue",
        "lib/guard-mail-move.js:_checkFolderName",
        "lib/guard-mail-query.js:_checkScalar",
        "lib/guard-mail-sieve.js:_checkName",
        "lib/guard-mail-sieve.js:validate",
        // v0.9.20 — guardJwt.kidSafe runs the same control-char scan
        // against operator-supplied JWT `kid` values (defends header-
        // injection at the JWT-resolver boundary).
        "lib/guard-jwt.js:kidSafe",
        // v0.9.21 — guardAgentRegistry's _checkName runs the same
        // shape against operator-supplied agent registry names.
        "lib/guard-agent-registry.js:_checkName",
        // v0.9.22 — guardIdempotencyKey's validate runs the same scan
        // on operator-supplied idempotency keys.
        "lib/guard-idempotency-key.js:validate",
        // v0.9.24 — guardStreamArgs._checkCursorOpts walks operator-
        // supplied cursor opts with the same per-key recursion + scan.
        "lib/guard-stream-args.js:_checkCursorOpts",
        "lib/guard-stream-args.js:validate",
        // v0.9.25 — guardEventBusTopic / guardEventBusPayload validate
        // operator-supplied topic + payload at the bus boundary.
        "lib/guard-event-bus-topic.js:validate",
        "lib/guard-event-bus-payload.js:validate",
        "lib/guard-event-bus-payload.js:_checkType",
        // v0.9.26 — guardTenantId validates operator-supplied tenant ids.
        "lib/guard-tenant-id.js:validate",
        // v0.9.27 — guardSagaConfig validates saga-creation configs.
        "lib/guard-saga-config.js:validate",
        // v0.9.28 — guardPostureChain validates posture envelopes.
        "lib/guard-posture-chain.js:validate",
        // v0.9.29 — guardTraceContext validates W3C traceparent envelopes.
        "lib/guard-trace-context.js:validate",
        // v0.9.30 — guardSnapshotEnvelope validates snapshot envelopes.
        "lib/guard-snapshot-envelope.js:validate",
        // v0.9.32 — guardSmtpCommand validates SMTP command lines (smuggling
        // defense + per-verb shape per RFC 5321 §4.5.3.1).
        "lib/guard-smtp-command.js:validate",
        // v0.9.33 — mailRbl._validateZoneNames walks DNSBL/DNSWL zone
        // strings for the same control-char + non-ASCII refusal.
        "lib/mail-rbl.js:_validateZoneNames",
      ],
      reason: "Control-char codepoint scan: `for (i...) { code = s.charCodeAt(i); if (code < 32 || code === 127) throw }` against operator-supplied header values. Many domain validators (RFC 9470 step-up sf-string quote, RFC 9213 CDN-Cache-Control parser, W3C client hints, RFC 8689 TLS-Required parser, RFC 7235 bearer-auth realm, RFC 5322 §3.6.4 Message-Id, RFC 9051 IMAP folder names, RFC 5804 ManageSieve script names, RFC 5322 §3.6 header-value injection refusal in compose drafts, structural-filter scalar refusal). Each domain refuses the control-char shape but emits a domain-typed error code so callers can't conflate the verdict. Future consolidation candidate via a shared `validateOpts.refuseControlChars(s, label, ErrorClass, code)` helper.",
    },
    {
      // v0.9.20 — guardMail* family scaffolding cluster. Every member
      // shares the standard guard-family shape: PROFILES table +
      // COMPLIANCE_POSTURES table + _resolveProfile dispatcher +
      // validate() + compliancePosture(). The detector finds the same
      // skeleton across the 6 guard-mail files because the guard
      // contract MANDATES it (b.gateContract enforces the shape at
      // registration). Each member's profile body / posture vocab is
      // distinct; the scaffolding around it is the contract.
      mode:  "family-subset",
      files: [
        "lib/guard-mail-compose.js:_resolveProfile",
        "lib/guard-mail-compose.js:_anyRecipient",
        "lib/guard-mail-compose.js:_checkAddrList",
        "lib/guard-mail-compose.js:<top>",
        "lib/guard-mail-move.js:_resolveProfile",
        "lib/guard-mail-move.js:validate",
        "lib/guard-mail-move.js:<top>",
        "lib/guard-mail-query.js:_resolveProfile",
        "lib/guard-mail-query.js:validateActor",
        "lib/guard-mail-query.js:<top>",
        "lib/guard-mail-reply.js:_resolveProfile",
        "lib/guard-mail-reply.js:validate",
        "lib/guard-mail-reply.js:compliancePosture",
        "lib/guard-mail-reply.js:<top>",
        "lib/guard-mail-sieve.js:_resolveProfile",
        "lib/guard-mail-sieve.js:<top>",
        "lib/guard-mail-sieve.js:validate",
        // v0.9.21 — guardAgentRegistry follows the same family scaffolding.
        "lib/guard-agent-registry.js:_resolveProfile",
        "lib/guard-agent-registry.js:validate",
        "lib/guard-agent-registry.js:compliancePosture",
        "lib/guard-agent-registry.js:<top>",
        "lib/guard-message-id.js:_resolveProfile",
        "lib/guard-message-id.js:compliancePosture",
        "lib/guard-message-id.js:validate",
        // v0.9.36 — guardEnvelope shares the family scaffolding;
        // PROFILES + COMPLIANCE_POSTURES + check() body.
        "lib/guard-envelope.js:<top>",
        "lib/guard-envelope.js:check",
        "lib/guard-envelope.js:compliancePosture",
        // v0.9.37 — guardDsn shares the family scaffolding;
        // PROFILES + COMPLIANCE_POSTURES + parse() body +
        // _resolveProfile dispatcher.
        "lib/guard-dsn.js:<top>",
        "lib/guard-dsn.js:parse",
        "lib/guard-dsn.js:_resolveProfile",
        "lib/guard-dsn.js:compliancePosture",
        // v0.9.39 — guardListUnsubscribe shares the family
        // scaffolding; validate() + _resolveProfile + posture
        // cascade.
        "lib/guard-list-unsubscribe.js:<top>",
        "lib/guard-list-unsubscribe.js:validate",
        "lib/guard-list-unsubscribe.js:_resolveProfile",
        "lib/guard-list-unsubscribe.js:compliancePosture",
        // v0.9.40 — guardListId shares the family scaffolding;
        // validate() + _resolveProfile + posture cascade.
        "lib/guard-list-id.js:<top>",
        "lib/guard-list-id.js:validate",
        "lib/guard-list-id.js:_resolveProfile",
        "lib/guard-list-id.js:compliancePosture",
        // v0.9.54 — guardJmap shares the family scaffolding;
        // validate() + _resolveProfile + posture cascade against
        // the RFC 8620 / RFC 8621 wire-protocol shape.
        "lib/guard-jmap.js:<top>",
        "lib/guard-jmap.js:validate",
        "lib/guard-jmap.js:compliancePosture",
      ],
      reason: "Guard-family scaffolding required by `b.gateContract` — every guard ships PROFILES (strict/balanced/permissive) + COMPLIANCE_POSTURES (hipaa/pci-dss/gdpr/soc2) + _resolveProfile dispatcher + a top-level @module JSDoc block. Each member's profile body / posture vocab / validate() body is domain-distinct; the surrounding skeleton is the family contract. Consolidation would erase the per-guard validation rules and break the `b.guardAll` registration pattern.",
    },
    {
      // v0.9.21 — guard-agent-registry's _checkName / _checkKind /
      // validate all share token shape with the guard-mail-* family
      // members at their input-validation lines (PROFILES check + name
      // shape scan + opts.kind check). Wildcard match because the
      // duplicate detector reports several different enclosing fns
      // depending on which line in each file's similar-shape block
      // happened to be the centroid.
      mode:  "family-subset",
      files: [
        "lib/guard-agent-registry.js:*",
        "lib/guard-idempotency-key.js:*",
        "lib/guard-jmap.js:*",
        "lib/guard-mail-compose.js:*",
        "lib/guard-mail-move.js:*",
        "lib/guard-mail-query.js:*",
        "lib/guard-mail-reply.js:*",
        "lib/guard-mail-sieve.js:*",
        "lib/guard-message-id.js:*",
        "lib/guard-stream-args.js:*",
        "lib/guard-event-bus-topic.js:*",
        "lib/guard-event-bus-payload.js:*",
        "lib/guard-tenant-id.js:*",
        "lib/guard-saga-config.js:*",
        "lib/guard-posture-chain.js:*",
        "lib/guard-trace-context.js:*",
        "lib/guard-snapshot-envelope.js:*",
        "lib/guard-smtp-command.js:*",
        "lib/guard-envelope.js:*",
        "lib/guard-list-unsubscribe.js:*",
        "lib/guard-list-id.js:*",
        "lib/guard-dsn.js:*",
      ],
      reason: "Guard-family input-validation cluster — every guard ships the same overall input-validation shape (call _resolveProfile + scan operator-supplied input + throw domain-typed error). The duplicate detector's centroid picks different lines across the family files; the cluster is one family pattern, not seven independent ones.",
    },
    {
      // v0.9.22 — agent-idempotency._checkArgs (validate non-empty
      // string method+actorId pair) shares its tight if-cascade shape
      // with atomic-file's copyDirRecursive (validate string path),
      // ddl-change-control's approve/reject (validate operator),
      // deprecate.alias (validate names), totp.uri (validate label
      // shape). Each emits a distinct domain error class.
      mode:  "family-subset",
      files: [
        "lib/agent-idempotency.js:_checkArgs",
        "lib/agent-idempotency.js:_fingerprintArgs",
        "lib/agent-tenant.js:_sealField",
        "lib/atomic-file.js:copyDirRecursive",
        "lib/atomic-file.js:ensureDir",
        "lib/ddl-change-control.js:approve",
        "lib/ddl-change-control.js:reject",
        "lib/deprecate.js:alias",
        "lib/totp.js:uri",
        "lib/totp.js:verify",
      ],
      reason: "Validate-string-args cascade with throw-on-bad-shape. Each member is a distinct primitive (idempotency op args, agent-tenant per-tenant field seal, atomic-file dir traversal, DDL change-control vote, deprecate.alias name shape, RFC 6238 TOTP URI builder). Distinct error classes; consolidating would couple unrelated specs.",
    },
    {
      // v0.9.28 — agent-posture-chain._appendHop shares the Object.assign
      // + immutability-respecting return shape with api-snapshot.write,
      // break-glass.unsealRowAsService, deprecate.alias. Each domain
      // immutably evolves an input value + returns the new shape.
      mode:  "family-subset",
      files: [
        "lib/agent-posture-chain.js:_appendHop",
        "lib/api-snapshot.js:write",
        "lib/break-glass.js:unsealRowAsService",
        "lib/deprecate.js:alias",
      ],
      reason: "Immutable-evolve-and-return pattern. Each domain takes an input object, builds a new derived one via Object.assign + delta, returns the new shape without mutating the input. Posture-chain hop append, api-snapshot snapshot write, break-glass row unseal, deprecate name alias — all distinct domains with distinct error classes.",
    },
    {
      // v0.9.29 — guard-trace-context top-of-file block shares its
      // shape with guard-uuid + observability module headers (each
      // ships the same JSDoc + license + module-level constant
      // declaration shape).
      mode:  "family-subset",
      files: [
        "lib/guard-trace-context.js:<top>",
        "lib/guard-uuid.js:<top>",
        "lib/observability.js:_emit",
      ],
      reason: "Module top-of-file headers share the same JSDoc + license + require-block shingle across guard families + observability. Each module is a separate primitive with distinct concerns.",
    },
    {
      // v0.9.29 — dpop._b64urlDecode / compliance-sanctions._levenshteinMatch /
      // dora._classifyImpl share token-shape from internal helper bodies
      // (loop + transform + return). Distinct domains: RFC 9449 base64url
      // for DPoP proof, fuzzy match for sanctions, DORA Annex IV impact
      // classifier.
      mode:  "family-subset",
      files: [
        "lib/auth/dpop.js:_b64urlDecode",
        "lib/compliance-sanctions.js:_levenshteinMatch",
        "lib/dora.js:_classifyImpl",
      ],
      reason: "Loop + transform + return helper bodies. Distinct domain primitives — DPoP base64url decode (RFC 9449 §4.2), sanctions Levenshtein matcher, DORA Annex IV classifier. No shared substrate would help.",
    },
    {
      // v0.9.27 — multi-create / multi-validate cluster: per-domain
      // initialization shape. sd-jwt-vc-issuer.create + break-glass
      // policy validation + db dual-control declaration + DSR initiator
      // + middleware/assetlinks + network heartbeat start. Each is a
      // separate domain primitive; validate-then-init-then-emit shape.
      mode:  "family-subset",
      files: [
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/auth/oid4vp.js:_validateDcql",
        "lib/auth/oid4vp.js:create",
        "lib/auth/step-up.js:parseAuthorizationDetails",
        "lib/break-glass.js:_validatePolicySet",
        "lib/db.js:declareRequireDualControl",
        "lib/dsr.js:create",
        "lib/middleware/assetlinks.js:create",
        "lib/network-heartbeat.js:start",
        "lib/network-heartbeat.js:_validateTarget",
        "lib/guard-saga-config.js:validate",
        "lib/guard-mail-compose.js:_checkBody",
        "lib/mail-auth.js:authResultsEmit",
        "lib/mail-auth.js:arcEvaluate",
        "lib/guard-mail-move.js:validate",
        "lib/guard-posture-chain.js:validate",
      ],
      reason: "Validate-then-init-then-emit factory shape. Each domain (RFC 7515 sd-jwt-vc-issuer / RFC 11 oid4vp DCQL / RFC 9470 step-up authz-details / break-glass policy / DDL dual-control / DSR initiator / Digital Asset Links / network heartbeat / saga config / mail compose body) does opts-validation + state-init + sometimes audit-emit at the create boundary. Distinct error classes; consolidation would couple unrelated specs.",
    },
    {
      // v0.9.26 — agent-tenant._checkDestroyPreconditions shares the
      // four-required-string-fields cascade shape with dpop.verify,
      // backup.scheduleTest, break-glass._validatePolicySet, DDL
      // change-control.propose, fda-21cfr11._validateSignatureInput,
      // incident-report.open, sd-jwt-vc-holder.store. Each domain
      // requires different fields and emits a distinct typed error.
      mode:  "family-subset",
      files: [
        "lib/agent-tenant.js:_checkDestroyPreconditions",
        "lib/agent-idempotency.js:_put",
        "lib/auth/dpop.js:verify",
        "lib/auth/sd-jwt-vc-holder.js:store",
        "lib/backup/index.js:scheduleTest",
        "lib/break-glass.js:_validatePolicySet",
        "lib/compliance-sanctions.js:screen",
        "lib/ddl-change-control.js:propose",
        "lib/dora.js:_validateReportInput",
        "lib/fda-21cfr11.js:_validateSignatureInput",
        "lib/guard-event-bus-payload.js:validate",
        "lib/guard-mail-query.js:validateActor",
        "lib/guard-mail-reply.js:validate",
        "lib/guard-saga-config.js:validate",
        "lib/guard-snapshot-envelope.js:validate",
        "lib/guard-trace-context.js:validate",
        "lib/incident-report.js:open",
        // v0.9.34 — mailGreylist.check validates the ctx triplet
        // (ip + mailFrom + rcptTo) before fingerprint hashing.
        "lib/mail-greylist.js:check",
        // v0.9.35 — mailHelo.evaluate validates the HELO/EHLO claim
        // (ip + claimedName + resolver) before shape + FCrDNS checks.
        "lib/mail-helo.js:evaluate",
        // v0.9.36 — guardEnvelope.check validates the From / SPF /
        // DKIM alignment per RFC 7489 §3.1.
        "lib/guard-envelope.js:check",
        // v0.9.39 — guardListUnsubscribe.validate validates the
        // List-Unsubscribe / List-Unsubscribe-Post header pair.
        "lib/guard-list-unsubscribe.js:validate",
      ],
      reason: "Per-domain validation-field cascade for required-args + throw-typed-error pattern. Each member enforces a different field tuple (destroy preconditions: stepUpToken/dualControlApprover/reason/actor; DPoP verify; backup test schedule; break-glass policy set; DDL change proposal; 21 CFR Part 11 signer fields; sd-jwt-vc holder store). Consolidation would couple unrelated regulatory specs.",
    },
    {
      // v0.9.21 — agent-orchestrator.spawnConsumers + mail-agent.consumer
      // + cra-report.conformityAssessment all build operator-supplied
      // input → arg shape with similar opts-validation cascades.
      mode:  "family-subset",
      files: [
        "lib/agent-orchestrator.js:_spawnConsumers",
        "lib/agent-orchestrator.js:create",
        "lib/agent-idempotency.js:create",
        "lib/agent-tenant.js:create",
        "lib/agent-snapshot.js:create",
        "lib/cra-report.js:conformityAssessment",
        "lib/mail-agent.js:consumer",
        // v0.9.31 — network-dns-resolver.create runs the same opts
        // validation + closure-capture prelude.
        "lib/network-dns-resolver.js:create",
        "lib/network-dns-resolver.js:<top>",
        "lib/agent-idempotency.js:<top>",
        "lib/agent-snapshot.js:<top>",
        // v0.9.34 — mailGreylist.create runs the same opts-validation
        // prelude + module-header scaffolding.
        "lib/mail-greylist.js:create",
        "lib/mail-greylist.js:<top>",
        // v0.9.33 — mailRbl <top> shares the mail-family PROFILES +
        // posture-cascade scaffolding with mail-greylist + mail-helo.
        "lib/mail-rbl.js:<top>",
        // v0.9.35 — mailHelo evaluate + <top> shares the same family
        // scaffolding.
        "lib/mail-helo.js:<top>",
        "lib/mail-helo.js:evaluate",
        // v0.9.36 — guardEnvelope.check runs the same opts-validation
        // prelude.
        "lib/guard-envelope.js:check",
        // v0.9.33 — mailRbl.create also matches this prelude shape;
        // primary allowlist for create is in the openapi/asyncapi
        // family entry below, listed here too for the 4-file cluster
        // that joins guard-envelope.check + mail-greylist.create +
        // mail-helo.evaluate + mail-rbl.create.
        "lib/mail-rbl.js:create",
      ],
      reason: "Consumer / report-creation factory prelude — operator opts validated, default values filled, internal state captured into closure. Each domain emits distinct error classes (AgentOrchestratorError / AgentIdempotencyError / AgentTenantError / CraReportError / MailAgentError) and registers a different op shape; consolidation would couple unrelated specs.",
    },
    {
      // v0.9.20 — guardMailQuery.validateActor shares the
      // missing-field-cascade shape with several compliance/auth
      // validators. Each domain requires a distinct posture-field
      // tuple (HIPAA purposeOfUse, PCI pciScope, GDPR lawfulBasis,
      // DORA report fields, FDA 21 CFR Part 11 signer fields, DPoP
      // jwk canonicalization). Distinct error classes.
      mode:  "family-subset",
      files: [
        "lib/auth/dpop.js:verify",
        "lib/auth/sd-jwt-vc-holder.js:store",
        "lib/compliance-sanctions.js:screen",
        "lib/dora.js:_validateReportInput",
        "lib/fda-21cfr11.js:_validateSignatureInput",
        "lib/guard-mail-query.js:validateActor",
        "lib/guard-mail-reply.js:validate",
        "lib/guard-saga-config.js:validate",
        "lib/guard-trace-context.js:validate",
        "lib/incident-report.js:open",
      ],
      reason: "Per-domain validation-field cascade against operator-supplied input objects — each member walks a fixed list of required fields, calls `if (typeof obj.field !== \"string\" || obj.field.length === 0) throw <DomainError>(\"<code>\", \"<message>\")`. Distinct domain error classes + distinct required-field sets (DPoP canonical JWK, sd-jwt-vc holder, sanctions screening, DORA, 21 CFR Part 11, posture actor fields, incident-report). Consolidation would couple unrelated specs.",
    },
    {
      // v0.9.20 — guardMailQuery shares the structural-walker shape
      // with cloud-events + mail-arf parsers.
      mode:  "family-subset",
      files: [
        "lib/cloud-events.js:parse",
        "lib/guard-mail-query.js:validateActor",
        "lib/mail-arf.js:parse",
      ],
      reason: "Per-domain shape validators with required-field + type-check cascades — CloudEvents 1.0 envelope, RFC 5965 ARF report, mail-query actor posture binding. Each enforces a different field vocabulary and emits a domain-typed error code on a missing/malformed field.",
    },
    {
      files: [
        "lib/a2a-tasks.js:_emitAudit",
        "lib/mcp-tool-registry.js:_emitAudit",
        "lib/middleware/idempotency-key.js:_emitAudit",
      ],
      reason: "Per-primitive `_emitAudit` audit-wrapper closures — three different audit namespaces (a2a / mcp.tool_registry / idempotency) each binding a try/catch around `audit().safeEmit({ action, outcome, metadata })`. Future consolidation candidate (matches validateOpts.makeNamespacedEmitters which several other primitives already use); allowlisted here so the v0.8.85 ship doesn't drift into refactoring three callers in the same patch.",
    },
    {
      mode: "family-subset",
      files: [
        "lib/cache-status.js:parse",
        "lib/cdn-cache-control.js:parse",
        "lib/client-hints.js:_parseBrandMember",
        "lib/mail-auth.js:_parseArcTagList",
        "lib/mail-auth.js:_parseDmarcRecord",
        "lib/mail-bimi.js:parseRecord",
        "lib/mail-dkim.js:_parseDkimTagList",
        "lib/network-smtp-policy.js:_parseStsPolicy",
        // v0.9.19 — safeMime's Content-Type / Content-Disposition
        // parameter parser shares the tag-list-shape skeleton.
        "lib/safe-mime.js:_parseContentType",
        "lib/safe-mime.js:_filenameFromHeaders",
      ],
      reason: "RFC structured-field tag-list parser scaffolding — split on top-level separator + handle quoted strings + extract key=value pairs. Each call site enforces a different RFC's tag-name vocabulary (RFC 9211 Cache-Status; RFC 9213 CDN-Cache-Control; RFC 8941 Sec-CH-UA brand-list; RFC 8617 ARC tag-set; RFC 7489 DMARC record; RFC 9091 BIMI record; RFC 6376 DKIM-Signature; RFC 8461 MTA-STS policy; RFC 2045/2231 MIME content-type + disposition). Future consolidation candidate but each site emits domain-typed output (different field vocabulary, different error class, different shape) that consolidation would erase.",
    },
    {
      mode: "family-subset",
      files: [
        "lib/auth/step-up.js:parseChallenge",
        "lib/cdn-cache-control.js:parse",
        "lib/cookies.js:parse",
        "lib/cookies.js:parseSafe",
        "lib/network-tls.js:_normalizeIpForCompare",
        "lib/safe-mime.js:_parseContentType",
        "lib/safe-mime.js:_filenameFromHeaders",
      ],
      reason: "Token-list scanner scaffolding: walk a comma-or-semicolon separated header, respect quoted-string boundaries via depth/inQuote state machine, emit per-piece key/value. Each call site enforces a different grammar (RFC 9470 step-up sf-Item challenges, RFC 9213 cache-control directive list, RFC 6265 Set-Cookie header, IPv6 normalization, RFC 2045/2231 MIME parameters). Consolidating would couple unrelated wire formats.",
    },
    {
      mode: "family-subset",
      files: [
        "lib/mail-auth.js:_parseHeaderLines",
        "lib/mime-parse.js:parseHeaderBlock",
        "lib/safe-mime.js:_splitHeaderLines",
      ],
      reason: "RFC 5322 §2.2.3 header continuation-line unfolding — each module needs to walk a header block + join WSP-prefixed continuation lines to the prior header. mail-auth.js drives DKIM signature parsing (RFC 6376 §3.5 — c=relaxed canonicalization needs the unfolded header view); mime-parse.js drives DSN/MDN flows (intentionally narrow scope — RFC 5322 + RFC 2045 minimal reader, no recursion, no decoding); safe-mime.js drives the bounded mail-stack parser (recursive multipart, RFC 2047 decoding, charset + CTE allowlists, every cap). The three sites cannot consolidate because mail-auth.js needs canonicalization-aware whitespace handling, mime-parse.js is the legacy narrow path, and safe-mime.js applies the operator's `maxHeaderLineBytes` cap per parse call — these are three different parser contracts. Future consolidation candidate when mime-parse.js retires (post-v1.0).",
    },
    {
      mode: "family-subset",
      files: [
        "lib/client-hints.js:acceptList",
        "lib/middleware/require-content-type.js:_normalizeAllowed",
        "lib/router.js:_matchCompiled",
        "lib/sandbox.js:_validateAllowed",
        "lib/watcher.js:_compileIgnore",
      ],
      reason: "Iterate operator-supplied string array, lowercase + dedupe + emit canonical form. Each call site enforces domain-specific vocabulary (client-hint header names against KNOWN_HINTS allowlist, MIME types against parse rules, route pattern compilation, sandbox path normalization, watcher glob normalization). Consolidating would erase the per-domain canonicalization rules.",
    },
    {
      mode: "family-subset",
      files: [
        "lib/cdn-cache-control.js:parse",
        "lib/client-hints.js:_parseBrandMember",
        "lib/http-client-cache.js:_parseCacheControl",
        "lib/middleware/tus-upload.js:_parseMetadata",
        "lib/request-helpers.js:parseQualityList",
      ],
      reason: "Comma-separated header value parser walking pieces and splitting on `=` per piece. Each enforces a different grammar (RFC 9213 directive list, RFC 9111 Cache-Control directives, Sec-CH-UA brand-member params, RFC 7240/tus.io upload metadata, RFC 9110 quality-list / Accept-* header). Consolidating would couple unrelated header families.",
    },
    {
      mode: "family-subset",
      files: [
        // v0.8.62 federation / VC primitives — every member shares the
        // standard primitive scaffolding with the rest of the lib/ tree:
        //   - validateOpts.requireNonEmptyString cascade at function entry
        //   - JWS header / payload base64url-decode + signature-verify shape
        //   - httpClient.request(...) → safeJson.parse error-body fallback
        //   - per-namespace _emitAudit / _emitMetric closures bound via
        //     validateOpts.makeNamespacedEmitters
        // The duplicate-block detector finds the substrate shape across
        // many domains (saml ↔ oid4vp ↔ oid4vci ↔ federation ↔ ciba ↔
        // sd-jwt-vc ↔ existing audit-daily-review / cluster / cloud-
        // events / mail-auth / network-smtp-policy primitives). Each
        // domain's error class + audit namespace + protocol-specific
        // claim validation is distinct; consolidating would couple
        // unrelated specs.
        // Sites populated from HS_CLUSTER_MIGRATE=1 dump.
        "lib/auth/saml.js:create",
        "lib/auth/saml.js:_verifyXmldsig",
        "lib/auth/oid4vci.js:create",
        "lib/auth/oid4vci.js:_verifyProofJwt",
        "lib/auth/oid4vci.js:createCredentialOffer",
        "lib/auth/oid4vci.js:exchangePreAuthorizedCode",
        // v0.8.85 — MCP tool registry + A2A tasks share the federation
        // primitive scaffolding (validateOpts.requireNonEmptyString
        // cascade + canonical-JSON envelope shape + JSON-RPC dispatch).
        "lib/mcp-tool-registry.js:create",
        "lib/mcp-tool-registry.js:verifyCall",
        "lib/mcp-tool-registry.js:signCall",
        "lib/a2a-tasks.js:_readBody",
        "lib/a2a-tasks.js:send",
        "lib/a2a-tasks.js:middlewareTasks",
        "lib/a2a-tasks.js:_jsonRpc",
        "lib/ai-adverse-decision.js:wrap",
        // v0.8.86 — HTTP-hygiene primitives share scaffolding.
        "lib/middleware/no-cache.js:create",
        "lib/cache-status.js:entryString",
        "lib/server-timing.js:create",
        "lib/auth/oid4vp.js:_validateDcql",
        "lib/auth/oid4vp.js:matchDcql",
        "lib/auth/openid-federation.js:parseEntityStatement",
        "lib/auth/ciba.js:startAuthentication",
        "lib/auth/ciba.js:parseNotification",
        "lib/auth/ciba.js:_registerInitialInterval",
        "lib/auth/ciba.js:pollToken",
        "lib/vex.js:document",
        "lib/vex.js:statement",
        "lib/mail-arc-sign.js:sign",
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/auth/step-up.js:parseAuthorizationDetails",
        "lib/compliance-eaa.js:create",
        "lib/data-act.js:shareWithThirdParty",
        "lib/data-act.js:recordSwitchRequest",
        "lib/db.js:declareRequireDualControl",
        // v0.8.77 — OAuth resource-server / SCIM / protected-resource-metadata
        // additions share the standard primitive scaffolding
        "lib/auth/oauth.js:pollDeviceCode",
        "lib/auth/oauth.js:registerClient",
        "lib/auth/oauth.js:exchangeToken",
        "lib/middleware/protected-resource-metadata.js:create",
        "lib/backup/index.js:scheduleTest",
        "lib/restore-rollback.js:rollback",
        // v0.9.13 — b.metrics.snapshot writer shares the scheduleTest/rollback
        // / exchangeToken interval+stop closure scaffold
        "lib/metrics.js:snapshotStartWriter",
        "lib/auth/sd-jwt-vc-holder.js:store",
        // Pre-v0.8.62 sites the new primitives share substrate with
        "lib/api-key.js:_validateIssueOpts",
        "lib/audit-daily-review.js:create",
        "lib/cloud-events.js:wrap",
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/daemon.js:_validateStartOpts",
        "lib/daemon.js:_validateStopOpts",
        "lib/ddl-change-control.js:create",
        "lib/external-db-migrate.js:create",
        "lib/fda-21cfr11.js:posture",
        "lib/fdx.js:consentReceipt",
        "lib/file-upload.js:_validateCreateOpts",
        "lib/http-message-signature.js:_parseUrl",
        "lib/mail-auth.js:dmarcParseAggregateReport",
        "lib/middleware/db-role-for.js:create",
        "lib/middleware/tus-upload.js:create",
        "lib/network-heartbeat.js:_validateTarget",
        "lib/network-smtp-policy.js:tlsRptParseReport",
        "lib/observability-tracer.js:create",
        "lib/outbox.js:create",
        "lib/redact.js:installOutboundDlp",
        "lib/restore-rollback.js:swap",
        "lib/sec-cyber.js:eightKArtifact",
        "lib/self-update.js:_validateVerifyOpts",
        "lib/static.js:_validateCreateOpts",
        "lib/vault/seal-pem-file.js:sealPemFile",
        "lib/auth/dpop.js:verify",
        "lib/auth/fido-mds3.js:_parseJws",
        "lib/auth/jwt.js:decode",
        "lib/auth/oauth.js:verifyIdToken",
        "lib/auth/oauth.js:_postForm",
        "lib/auth/oauth.js:verifyBackchannelLogoutToken",
        "lib/auth/sd-jwt-vc.js:verify",
        "lib/dsr.js:submit",
      ],
      reason: "v0.8.62 federation / VC primitive family — saml / oid4vci / oid4vp / openid-federation / ciba / db-file-lifecycle share the standard primitive scaffolding (validateOpts cascade, JWS header decode + signature verify, httpClient.request with safeJson.parse fallback, _emitAudit / _emitMetric via makeNamespacedEmitters) with the rest of the lib/ tree. Each protocol's claim validation + per-domain error class + audit namespace differs; consolidating would couple unrelated specs and lose per-domain operator-readable error codes.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/deprecate.js:_validateOpts",
        "lib/openapi-paths-builder.js:_normaliseParameter",
        "lib/openapi-paths-builder.js:_normaliseRequestBody",
        "lib/openapi-paths-builder.js:_normaliseResponses",
        "lib/openapi.js:_validateServerEntry",
        "lib/openapi.js:parse",
        "lib/asyncapi.js:_addChannel",
        "lib/asyncapi.js:_normaliseMessage",
        "lib/asyncapi.js:_validateServerEntry",
        "lib/asyncapi.js:parse",
        "lib/asyncapi.js:create",
        "lib/asyncapi-bindings.js:kafka",
        "lib/openapi.js:create",
        // v0.9.33 — mailRbl.create shares the same opts-validation
        // prelude as the doc-generation create() factories.
        "lib/mail-rbl.js:create",
        "lib/vex.js:document",
        "lib/mail.js:resendTransport",
        "lib/inbox.js:_validateReceiveOpts",
        "lib/mail-arc-sign.js:<unknown>",
        "lib/a2a.js:createCard",
        "lib/a2a.js:_validateCardShape",
        "lib/budr.js:declare",
        "lib/auth/saml.js:create",
        "lib/auth/oid4vci.js:create",
        "lib/auth/oid4vp.js:create",
        "lib/auth/openid-federation.js:buildTrustChain",
        "lib/auth/ciba.js:create",
        "lib/db-file-lifecycle.js:fileLifecycle",
        "lib/middleware/protected-resource-metadata.js:create",
      ],
      reason: "validateOpts.requireNonEmptyString-prelude scaffold — primitives gate operator-supplied opts with the same `validateOpts.requireNonEmptyString(opts.X, ..., ErrorClass, code)` cascade. Each domain's error class differs (DeprecateError / OpenApiError / AsyncApiError / MailError / InboxError / A2aError / BudrError / AuthError / DbFileLifecycleError); consolidating would lose the per-module error code.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/daemon.js:_readPidFile",
        "lib/daemon.js:_validateStartOpts",
        "lib/data-act.js:shareWithThirdParty",
        "lib/mail-mdn.js:_generateBoundary",
        "lib/mail-mdn.js:<unknown>",
        "lib/self-update.js:poll",
        "lib/self-update.js:_validateVerifyOpts",
        "lib/watcher.js:_compileIgnore",
        "lib/watcher.js:_detectAutoMode",
      ],
      reason: "Functional 50-token shingles surface across daemon / mail-mdn / self-update / watcher because every primitive opens with the same `function name(opts) { validateOpts.X(...) }` scaffold and ends with `try { ... } catch (_e) { return null; }` and per-module crypto.generateToken / Date.now() / fs.readFileSync line shapes. Consolidating the four primitives would lose per-domain error class + permissions semantics — the duplication is structural to the per-module create() entry-point.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/asyncapi-traits.js:_mergeKey",
        "lib/flag-evaluation-context.js:merge",
        "lib/render.js:_mergedHeaders",
      ],
      reason: "Object-property iteration with hasOwnProperty guard idiom — `for (var k in X) if (Object.prototype.hasOwnProperty.call(X, k)) ...` is the standard Object-pollution-defense walk. Three different domains (AsyncAPI trait merge, flag-evaluation context normalisation, render template-context walk); consolidating would couple unrelated primitives.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/compliance-ai-act-prohibited.js:getPractice",
        "lib/compliance-ai-act-risk.js:getAnnexIII",
        "lib/compliance-ai-act-logging.js:<unknown>",
        "lib/compliance-ai-act.js:<unknown>",
        "lib/compliance-ai-act-transparency.js:<unknown>",
        "lib/guard-all.js:_byName",
      ],
      reason: "EU AI Act primitive family + guard-all linear-scan idiom — sibling modules sharing the linear catalog-walk shape (`for (var i = 0; i < ARR.length; i += 1) { if (ARR[i].id === id) return ARR[i]; } return null;`). The AI-Act catalogs diverge (Article 5 prohibited practices vs Annex III high-risk rows vs Article 12 logging fields vs Article 50 transparency banners) and guard-all walks the registered guard-list; consolidating would lose per-domain structure.",
    },
    {
      files: [
        "lib/compliance-ai-act.js:annexIVScaffold",
        "lib/gate-contract.js:defineGate",
        "lib/mail-auth.js:_shapeAggregateReport",
      ],
      reason: "Long opts-passthrough block where each line is `field: opts.field || null` with the same null-fallback shape. AI-Act annexIVScaffold builds the Annex IV section-1 record; gate-contract assembles content-safety profile; mail-auth builds an authentication-results header. Three different schemas; not consolidatable.",
    },
    {
      files: [
        "lib/guard-all.js:_resolveActiveGuards",
        "lib/middleware/index.js:<top>",
        "lib/websocket-channels.js:create",
      ],
      reason: "Long `field: opts.field` config-passthrough chain coincidentally shingles. guard-all assembles per-guard opts (gate-contract vocabulary); middleware/index forwards createApp opts to per-middleware factories; websocket-channels forwards channel-broker opts. Three different domains, three different vocabulary lists — not consolidatable.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/middleware/security-txt.js:create",
        "lib/middleware/assetlinks.js:create",
        "lib/middleware/web-app-manifest.js:create",
        "lib/middleware/tus-upload.js:_handleDelete",
      ],
      reason: "Static/well-known + TUS-collection middleware family — security.txt / assetlinks / web-app-manifest / tus-upload all gate on a fixed mountPath then branch on req.method, share the headersSent guard + writeHead/end+observability emit shape. Four different domains, four different response bodies and lifecycle semantics. Future consolidation candidate when a 5th well-known emitter ships.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/password.js:check",
        "lib/middleware/tus-upload.js:_parseMetadata",
        "lib/request-helpers.js:parseQualityList",
        "lib/observability.js:_parseBaggage",
        "lib/observability.js:_parseTracestate",
      ],
      reason: "Argon2id PHC-encoder/decoder + TUS metadata + Cookie-attribute parser + W3C tracestate parser independently iterate over `key=value` / `key value` token pairs and split on the first separator. The 50-token shingle is the loop+split skeleton; the per-domain semantics (Argon2 cost params vs TUS metadata vs cookie attrs vs trace vendor pairs) are different enough that consolidating would erode each parser's domain validation.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/passkey.js:_validateExpectedOrigin",
        "lib/mail-arc-sign.js:sign",
        "lib/middleware/require-methods.js:create",
        "lib/network-tls.js:buildOptions",
        "lib/redact.js:classifyDefaults",
        "lib/ws-client.js:connect",
        // v0.9.20 — b.guardMailCompose._checkAddrList walks the
        // operator-supplied address array with the same shape.
        "lib/guard-mail-compose.js:_checkAddrList",
      ],
      reason: "Array-of-non-empty-strings validation scaffolding — `if (Array.isArray(v)) { if (v.length === 0) throw; for (i...) if (typeof v[i] !== 'string' || v[i].length === 0) throw }`. Each call site enforces a domain-specific list-element grammar (WebAuthn expected-origins, RFC 8617 ARC AuthServId list, RFC 9110 method allowlist, RFC 8446 TLS cipher list, redact field paths, RFC 6455 WS subprotocol list); the array shape is the same but the element-level grammar differs. validateOpts.optionalNonEmptyStringArray covers the simpler optional shape; this strict 'required-non-empty-array' variant could extract but each domain emits domain-typed error codes consolidation would erase.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/api-key.js:_validateIssueOpts",
        "lib/audit-daily-review.js:create",
        "lib/auth-bot-challenge.js:create",
        "lib/auth/jwt.js:_requireNumericDate",
        "lib/cloud-events.js:wrap",
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/daemon.js:_validateStartOpts",
        "lib/daemon.js:_validateStopOpts",
        "lib/ddl-change-control.js:create",
        "lib/dsr.js:create",
        "lib/external-db.js:_requirePosInt",
        "lib/external-db-migrate.js:create",
        "lib/fda-21cfr11.js:posture",
        "lib/fdx.js:bind",
        "lib/fdx.js:consentReceipt",
        "lib/file-upload.js:_validateCreateOpts",
        "lib/http-client.js:_requirePositiveInt",
        "lib/http-client.js:_validateDownloadOpts",
        "lib/http-client.js:_validateUploadOpts",
        "lib/http-client-cache.js:create",
        "lib/http-client-cache.js:memoryStore",
        "lib/mail-arc-sign.js:sign",
        "lib/middleware/db-role-for.js:create",
        "lib/middleware/dpop.js:create",
        "lib/middleware/security-txt.js:create",
        "lib/middleware/tus-upload.js:_handleDelete",
        "lib/middleware/tus-upload.js:create",
        "lib/middleware/web-app-manifest.js:create",
        "lib/observability-otlp-exporter.js:<unknown>",
        "lib/outbox.js:create",
        "lib/redact.js:installOutboundDlp",
        "lib/retention.js:_validateRule",
        "lib/sec-cyber.js:eightKArtifact",
        "lib/self-update.js:_validateVerifyOpts",
        "lib/static.js:_validateCreateOpts",
        "lib/tcpa-10dlc.js:recordConsent",
        "lib/vault/seal-pem-file.js:sealPemFile",
        "lib/watcher.js:_validateOpts",
        "lib/auth/saml.js:create",
        "lib/auth/oid4vci.js:create",
        "lib/auth/oid4vp.js:create",
        "lib/auth/openid-federation.js:buildTrustChain",
        "lib/auth/openid-federation.js:resolveLeaf",
        "lib/auth/ciba.js:create",
        "lib/db-file-lifecycle.js:fileLifecycle",
        "lib/vex.js:document",
      ],
      reason: "validateOpts factory prelude — every factory primitive runs the same `validateOpts.requireNonEmptyString(opts.X, label, ErrorClass, code) + validateOpts.optionalY + closure-capture` shape because they share the operator-typo handling convention. Many different domains with distinct error classes (ApiKeyError / AuditError / FdaError / FdxError / HttpClientError / MailArcSignError / OutboxError / RetentionError / Self-Update / Static / TcpaError / VaultError / VexError / WatcherError / AuthError / DbFileLifecycleError / ...); consolidating would push validation past the call boundary where the operator's typo gets the wrong error code. The cluster grows with every new factory primitive — family-subset mode allows the existing entries to keep matching as new sites join.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/cloud-events.js:wrap",
        "lib/file-upload.js:_validateCreateOpts",
        "lib/observability-otlp-exporter.js:<unknown>",
        "lib/static.js:_validateCreateOpts",
        "lib/sec-cyber.js:eightKArtifact",
        "lib/fdx.js:bind",
        "lib/fdx.js:consentReceipt",
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/middleware/dpop.js:create",
        "lib/outbox.js:create",
        "lib/vault/seal-pem-file.js:sealPemFile",
        "lib/ai-adverse-decision.js:wrap",
        "lib/vex.js:document",
        "lib/watcher.js:_validateOpts",
      ],
      reason: "JSON-envelope serializer prelude — cloud-events / file-upload / otlp-exporter / static / sec-cyber / fdx / compliance-sanctions-fetcher / dpop-middleware / outbox / vault-seal-pem-file / ai-adverse-decision / vex / watcher all build a `{ headers, body }` JSON envelope from operator opts via Object.assign + JSON.stringify; validate the resulting payload byte-length; return the rendered Buffer. Thirteen different domains, thirteen different content shapes; the 50-token shingle is the envelope-build skeleton.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/cloud-events.js:wrap",
        "lib/external-db-migrate.js:create",
        "lib/observability-otlp-exporter.js:<unknown>",
        "lib/observability-tracer.js:create",
        "lib/ai-adverse-decision.js:wrap",
      ],
      reason: "Object.assign + validateOpts shape — cloud-events / external-db-migrate / otlp-exporter / observability-tracer / ai-adverse-decision each define an opts validator that calls validateOpts(opts, [...allowed-keys], label) and then merges resource/scope-level defaults via Object.assign. Five different domains; the 50-token shingle is the validator+merge skeleton.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/cloud-events.js:<unknown>",
        "lib/observability-otlp-exporter.js:<unknown>",
        "lib/static.js:<unknown>",
        "lib/sec-cyber.js:eightKArtifact",
        "lib/fdx.js:consentReceipt",
      ],
      reason: "JSON envelope builder + Content-Type/Length response shape — cloud-events / otlp-exporter / static / sec-cyber / fdx all build a JSON-serializable response, compute Content-Length, set Content-Type, and emit observability.safeEvent on send. Five different domains, five different envelope payloads.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/file-upload.js:create",
        "lib/middleware/span-http-server.js:create",
        "lib/static.js:create",
      ],
      reason: "Response-lifecycle hook scaffold — file-upload / span-http-server / static each register `res.on('finish'|'close'|'error', _finish)` to fire a single closure on response completion regardless of which event terminates the response. Three different domains (chunk cleanup / span end / asset audit); the 50-token shingle is the listener wiring + idempotent-closure pattern.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/break-glass.js:policyGet",
        "lib/outbox.js:_processOnce",
        "lib/queue-local.js:dlqList",
      ],
      reason: "Backoff curve / repeating-tick worker scaffolding — break-glass / outbox / queue-local each spin a `safeAsync.repeating` worker that polls a backing store, claims rows under FOR UPDATE SKIP LOCKED, processes, and advances next_attempt_at via a `min(initial * factor^N, max)` exponential cap. Three independent domains with different schemas + different retry semantics; the 50-token shingle is the worker scaffold, not the domain logic.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/middleware/db-role-for.js:create",
        "lib/middleware/tus-upload.js:create",
        "lib/outbox.js:_emitAudit",
        "lib/outbox.js:create",
        "lib/dsr.js:create",
        "lib/compliance-sanctions.js:_emitAudit",
        "lib/compliance-sanctions.js:_emitMetric",
        "lib/compliance-sanctions.js:create",
        "lib/observability-otlp-exporter.js:_emitMetric",
        "lib/compliance-sanctions-fetcher.js:_emitAudit",
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/guard-html-wcag.js:audit",
        "lib/mail-dkim.js:create",
        "lib/mail-arc-sign.js:sign",
        "lib/auth/sd-jwt-vc-issuer.js:_emitAudit",
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/auth/sd-jwt-vc-holder.js:_emitAudit",
        "lib/auth/sd-jwt-vc-holder.js:create",
        "lib/auth/dpop.js:<unknown>",
        "lib/incident-report.js:_emitAudit",
        "lib/incident-report.js:_emitMetric",
        "lib/incident-report.js:create",
        "lib/incident-report.js:get",
        "lib/cra-report.js:_emitAudit",
        "lib/cra-report.js:create",
        "lib/nis2-report.js:_emitAudit",
        "lib/nis2-report.js:create",
        "lib/gdpr-ropa.js:_emitAudit",
        "lib/gdpr-ropa.js:create",
        "lib/gdpr-ropa.js:get",
        "lib/compliance-eaa.js:_emitAudit",
        "lib/compliance-eaa.js:create",
        "lib/middleware/bot-disclose.js:<unknown>",
        "lib/breach-deadline.js:_emitAudit",
        "lib/breach-deadline.js:createReporter",
        "lib/breach-deadline.js:get",
        "lib/ai-adverse-decision.js:_emitAudit",
        "lib/ai-adverse-decision.js:wrap",
        "lib/middleware/age-gate.js:_emitAudit",
        "lib/vault/seal-pem-file.js:_emitAudit",
        "lib/vault/seal-pem-file.js:sealPemFile",
        "lib/budr.js:declare",
        "lib/vex.js:document",
      ],
      reason: "Audit + observability emit prelude — every primitive wraps `audit.safeEmit` / `observability.safeEvent` calls in a try/catch+swallow because both are best-effort observability sinks. Different action vocabularies; consolidating would lose the per-primitive metric name.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/compliance-sanctions.js:_emitAudit",
        "lib/compliance-sanctions.js:_emitMetric",
        "lib/compliance-sanctions.js:create",
        "lib/compliance-sanctions.js:screen",
        "lib/dora.js:_validateReportInput",
        "lib/middleware/dpop.js:create",
        "lib/outbox.js:_emitAudit",
        "lib/outbox.js:create",
        "lib/static.js:_validateCreateOpts",
        "lib/compliance-sanctions-fetcher.js:_emitAudit",
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/dsr.js:_emitAudit",
        "lib/dsr.js:_emitMetric",
        "lib/dsr.js:create",
        "lib/auth/sd-jwt-vc-holder.js:_emitAudit",
        "lib/auth/sd-jwt-vc-holder.js:create",
        "lib/auth/sd-jwt-vc-holder.js:store",
        "lib/auth/sd-jwt-vc-issuer.js:_emitAudit",
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/middleware/daily-byte-quota.js:_emitAudit",
        "lib/middleware/daily-byte-quota.js:_shouldSkip",
        "lib/auth/access-lock.js:_emitAudit",
        "lib/auth/access-lock.js:_emitMetric",
        "lib/auth/access-lock.js:_isPassthrough",
        "lib/auth/access-lock.js:create",
        "lib/observability-otlp-exporter.js:_emitAudit",
        "lib/observability-otlp-exporter.js:_emitMetric",
        "lib/incident-report.js:_emitAudit",
        "lib/incident-report.js:_emitMetric",
        "lib/incident-report.js:create",
        "lib/incident-report.js:get",
        "lib/incident-report.js:open",
        "lib/cra-report.js:_emitAudit",
        "lib/cra-report.js:create",
        "lib/nis2-report.js:_emitAudit",
        "lib/nis2-report.js:create",
        "lib/gdpr-ropa.js:_emitAudit",
        "lib/gdpr-ropa.js:create",
        "lib/gdpr-ropa.js:get",
        "lib/compliance-eaa.js:_emitAudit",
        "lib/compliance-eaa.js:create",
        "lib/middleware/bot-disclose.js:_matches",
        "lib/breach-deadline.js:_emitAudit",
        "lib/breach-deadline.js:createReporter",
        "lib/breach-deadline.js:get",
        "lib/ai-adverse-decision.js:_emitAudit",
        "lib/ai-adverse-decision.js:wrap",
        "lib/middleware/age-gate.js:_emitAudit",
        "lib/middleware/age-gate.js:_shouldSkip",
        "lib/vault/seal-pem-file.js:_emitAudit",
        "lib/vault/seal-pem-file.js:sealPemFile",
        "lib/budr.js:declare",
      ],
      reason: "Try/catch + drop-silent observability emit — every primitive wraps `audit().safeEmit({ action, outcome, metadata })` in a try/catch+swallow per the validation-tier policy (drop-silent at hot-path observability sinks). The 50-token shingle is the swallow shape, not the domain logic.",
    },
    {
      mode:  "family-subset",
      files: ["lib/db.js:_tick", "lib/network-tls.js:_tick", "lib/ntp-check.js:_tick"],
      reason: "Periodic-monitor scaffolding — db.integrityMonitor / network-tls.expiryMonitor / ntpCheck.monitor each spin a `safeAsync.repeating` worker that performs a poll, emits an audit + observability event on every tick, fires an operator hook on threshold crossing, and returns a `.stop()` handle. Three different domains (SQLite corruption / TLS cert expiry / NTP clock drift); the 50-token shingle is the worker scaffold + emit shape, not the domain logic. Future consolidation candidate when a 4th periodic monitor lands.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/a2a-tasks.js:_readBody",
        "lib/auth/step-up.js:_quote",
        "lib/cache-status.js:_parseParamValue",
        "lib/client-hints.js:acceptList",
        "lib/daemon.js:_safeAuditEmit",
        "lib/guard-dsn.js:<top>",
        "lib/guard-dsn.js:_resolveProfile",
        "lib/guard-envelope.js:check",
        "lib/guard-idempotency-key.js:validate",
        "lib/guard-imap-command.js:<top>",
        "lib/guard-imap-command.js:validate",
        "lib/guard-jmap.js:<top>",
        "lib/guard-jmap.js:validate",
        "lib/guard-jwt.js:kidSafe",
        "lib/guard-list-id.js:<top>",
        "lib/guard-list-id.js:_refuse",
        "lib/guard-list-id.js:_resolveProfile",
        "lib/guard-list-unsubscribe.js:_resolveProfile",
        "lib/guard-list-unsubscribe.js:_verdict",
        "lib/guard-mail-compose.js:<top>",
        "lib/guard-mail-compose.js:_checkHeaderValue",
        "lib/guard-mail-move.js:<top>",
        "lib/guard-mail-move.js:_checkFolderName",
        "lib/guard-mail-query.js:<top>",
        "lib/guard-mail-sieve.js:<top>",
        "lib/guard-managesieve-command.js:<top>",
        "lib/guard-managesieve-command.js:validate",
        "lib/guard-message-id.js:validate",
        "lib/guard-pop3-command.js:<top>",
        "lib/guard-pop3-command.js:validate",
        "lib/guard-posture-chain.js:<top>",
        "lib/guard-posture-chain.js:validate",
        "lib/guard-smtp-command.js:<top>",
        "lib/guard-smtp-command.js:_parseAuthCommandSyntax",
        "lib/guard-smtp-command.js:_resolveProfile",
        "lib/guard-smtp-command.js:validate",
        "lib/guard-stream-args.js:<top>",
        "lib/keychain.js:_drain",
        "lib/mail-dav.js:_emit",
        "lib/mail-dav.js:_readBodyBytes",
        "lib/mail-greylist.js:create",
        "lib/mail-helo.js:evaluate",
        "lib/mail-rbl.js:create",
        "lib/mail-scan.js:create",
        "lib/mail-scan.js:scan",
        "lib/mail-server-imap.js:_emit",
        "lib/mail-server-imap.js:_handleAuthenticate",
        "lib/mail-server-imap.js:close",
        "lib/mail-server-imap.js:create",
        "lib/mail-server-imap.js:listen",
        "lib/mail-server-jmap.js:_emit",
        "lib/mail-server-jmap.js:create",
        "lib/mail-server-managesieve.js:_dispatch",
        "lib/mail-server-managesieve.js:_emit",
        "lib/mail-server-managesieve.js:close",
        "lib/mail-server-managesieve.js:create",
        "lib/mail-server-managesieve.js:listen",
        "lib/mail-server-mx.js:_emit",
        "lib/mail-server-mx.js:_validateDomainHardened",
        "lib/mail-server-mx.js:listen",
        "lib/mail-server-pop3.js:_dispatch",
        "lib/mail-server-pop3.js:_emit",
        "lib/mail-server-pop3.js:_handlePass",
        "lib/mail-server-pop3.js:close",
        "lib/mail-server-pop3.js:create",
        "lib/mail-server-pop3.js:listen",
        "lib/mail-server-submission.js:_emit",
        "lib/mail-server-submission.js:_handleAuth",
        "lib/mail-server-submission.js:_handleCommand",
        "lib/mail-server-submission.js:_validateDomainHardened",
        "lib/mail-server-submission.js:listen",
        "lib/mail-spam-score.js:_sanitizeReasons",
        "lib/mail-spam-score.js:create",
        "lib/middleware/bearer-auth.js:create",
        "lib/middleware/require-content-type.js:_normalizeAllowed",
        "lib/outbox.js:create",
        "lib/router.js:_matchCompiled",
        "lib/safe-dns.js:_decodeOpt",
        "lib/safe-dns.js:_resolveProfile",
        "lib/safe-ical.js:<top>",
        "lib/safe-ical.js:_parseContentLine",
        "lib/safe-ical.js:_stripDoubleQuotes",
        "lib/safe-icap.js:_detectThreat",
        "lib/safe-icap.js:_findHeaderEnd",
        "lib/safe-icap.js:_resolveProfile",
        "lib/safe-mime.js:_findHeaderBodySep",
        "lib/safe-smtp.js:findDotTerminator",
        "lib/safe-vcard.js:<top>",
        "lib/safe-vcard.js:_parseContentLine",
        "lib/safe-vcard.js:_stripDoubleQuotes",
        "lib/sandbox.js:_validateAllowed",
        "lib/self-update.js:<top>",
        "lib/self-update.js:_safeAuditEmit",
        "lib/watcher.js:_compileIgnore",
      ],
      reason: "v0.9.58 mail-stack bundle (multi-agent parallel ship: ManageSieve + ICAP + PGP/SMIME + DAV) — every new lib/ file written by the 4 sub-agents joins one or more existing family-subset clusters (guard-* validate / <top> banner shapes; mail-server-* listener scaffolds; safe-* line-folded parsers; emit-audit wrappers; resolveProfile dispatchers). Each underlying domain stays distinct (different RFCs, different wire grammars); the shared shingle is the framework's family-contract scaffolding (`b.gateContract` / listener template / safeBuffer.boundedChunkCollector / lazyRequire-audit / drop-silent emit). Consolidation into a single base module would couple unrelated wire-protocol grammars under one abstraction. Documented as one cluster rather than 49 individual family-subset entries because each cluster fingerprint is a subset of this union.",
    },
    {
      files: [
        "lib/auth/dpop.js:<unknown>",
        "lib/break-glass.js:<unknown>",
        "lib/middleware/security-txt.js:<unknown>",
      ],
      reason: "Generic input validation prelude — `if (typeof X !== 'string' || X.length === 0 || /[\\r\\n\\0]/.test(X)) throw` repeats across primitives that gate operator-supplied strings against header-injection bytes (DPoP htm/htu, break-glass reasons, security.txt field values). Three different error classes; the rejection reason is identical but the error code prefix is per-domain.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/auth/step-up.js:parseAuthorizationDetails",
        "lib/auth/step-up-policy.js:acr",
        "lib/auth/step-up-policy.js:acrAny",
        "lib/auth/step-up-policy.js:amr",
        "lib/break-glass.js:_validatePolicySet",
        "lib/dsr.js:create",
        "lib/middleware/assetlinks.js:create",
        "lib/middleware/require-methods.js:create",
        "lib/middleware/security-txt.js:_arrayOfStrings",
        "lib/network-dns.js:_clearCache",
        "lib/network-dns.js:setServers",
        "lib/network-heartbeat.js:_validateTarget",
        "lib/network-heartbeat.js:start",
        "lib/network-tls.js:setKeyShares",
        "lib/safe-schema.js:_tupleWithRest",
        "lib/safe-schema.js:chain",
        "lib/safe-schema.js:tuple",
        "lib/safe-schema.js:union",
        "lib/ws-client.js:connect",
        "lib/mail-arc-sign.js:sign",
      ],
      reason: "Non-empty-array opt validation prelude — `if (!Array.isArray(opts.X) || opts.X.length === 0) throw` plus per-element non-empty-string check repeats across primitives that take operator-supplied lists (sd-jwt-vc issuer keys, step-up acrValues / requiredAmr, step-up-policy acrAny / amr / requiredAmr atoms, require-methods HTTP-verb allowlist, security-txt contact lines, break-glass columns, dsr sources, assetlinks statements, DNS resolver IPs, heartbeat targets, TLS key shares, safe-schema enum values, ws-client subprotocols). Twelve different domains with file-specific error classes; consolidating would lose the per-module error code.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/file-upload.js:_validateCreateOpts",
        "lib/guard-html.js:<unknown>",
        "lib/static.js:_validateCreateOpts",
        "lib/cloud-events.js:wrap",
      ],
      reason: "Validate-opts scaffolding + per-primitive PROFILES literal block. file-upload and static open with the same `validateOpts.requireObject(...)` cascade; guard-html's PROFILES literal carries the same opt-name vocabulary as both; cloud-events.wrap performs the same require + optional cascade across spec attributes. Different create()-style entry shapes; the bodies diverge. Same conventional-shape false-positive as the prior validateOpts cluster.",
    },
    {
      files: ["lib/audit.js:<unknown>", "lib/guard-csv.js:<unknown>", "lib/guard-html.js:<unknown>"],
      reason: "Audit emission shape — `audit.emit({ event, outcome, metadata: { ... } })` carries identical token sequence across the audit primitive itself and any consumer that emits structured audit rows. guard-csv and guard-html each emit their own domain events; consolidation is impossible because the audit module IS the canonical emitter and the consumers cannot route through themselves.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/api-key.js:_validateIssueOpts",
        "lib/file-upload.js:_validateCreateOpts",
        "lib/static.js:_validateCreateOpts",
        "lib/cloud-events.js:wrap",
      ],
      reason: "_validateOpts function-prelude scaffolding — every primitive's create() opens with `function _validateXxxOpts(opts) { validateOpts.requireObject(opts, ..., XError); validateOpts.requireNonEmptyString(...); validateOpts.optionalXxx(...) }`. Same scaffolding by design; the cascade body differs per primitive's domain. Tracked as conventional-shape false-positive.",
    },
    {
      files: [
        "lib/api-key.js:<unknown>",
        "lib/guard-csv.js:<unknown>",
        "lib/guard-svg.js:<unknown>",
      ],
      reason: "Same conventional-shape scaffolding as the file-upload/static cluster — every primitive opens its create()/factory with the same `validateOpts.requireObject(...)` cascade plus per-domain numericBounds / requireNonEmptyString calls. The token sequence shingles across primitives that share the convention; the cascades' bodies (api-key columns vs csv profile-resolution vs svg compliance-posture lookup) diverge.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/mail-auth.js:_canonRelaxedHeader",
        "lib/mail-auth.js:_fetchDmarcRecord",
        "lib/mail-auth.js:_fetchSpfRecord",
        "lib/mail-auth.js:_parseArcTagList",
        "lib/mail-auth.js:_parseDmarcRecord",
        "lib/mail-auth.js:arcEvaluate",
        "lib/mail-auth.js:arcVerify",
        "lib/mail-dkim.js:_canonHeaderRelaxed",
        "lib/mail-dkim.js:_parseDkimTagList",
        "lib/mail-bimi.js:fetchPolicy",
        "lib/mail-bimi.js:parseRecord",
        "lib/mail-arc-sign.js:_canonRelaxedHeader",
        "lib/middleware/body-parser.js:_contentType",
        "lib/middleware/body-parser.js:_parseHeaderParams",
        "lib/middleware/body-parser.js:_parseMultipartHeaders",
        "lib/network-smtp-policy.js:_parseStsPolicy",
        "lib/network-smtp-policy.js:_fetchStsTxt",
        "lib/network-smtp-policy.js:tlsRptFetchPolicy",
        "lib/auth/step-up.js:parseChallenge",
        "lib/ai-pref.js:parseHeader",
        "lib/network-tls.js:_parseSanString",
      ],
      reason: "Generic key=value record-parsing idiom — split on delimiter, trim, split first '=' into key/value, lowercase, dispatch by key. Appears in DKIM-Signature tag-list parsing, DMARC record parsing, BIMI record parsing, MTA-STS policy text parsing, the body-parser content-type-parameter parser, the RFC 7235 / RFC 9470 WWW-Authenticate Bearer challenge parser, and Node's textual SAN format (`DNS:foo, IP Address:1.2.3.4`). Each module's value-coercion + policy-key-name set is genuinely different; the 5-line shape doesn't merit extraction.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/jwt.js:_b64urlEncode",
        "lib/auth/jwt.js:decode",
        "lib/auth/jwt-external.js:_b64urlDecode",
        "lib/auth/jwt-external.js:_verifyParamsForAlg",
        "lib/auth/jwt-external.js:verifyExternal",
        "lib/auth/oauth.js:_b64urlEncode",
        "lib/auth/oauth.js:_verifyParamsForAlg",
        "lib/auth/oauth.js:verifyIdToken",
        "lib/auth/dpop.js:_b64urlDecode",
        "lib/auth/dpop.js:_b64urlEncode",
        "lib/auth/dpop.js:_signParamsForAlg",
        "lib/auth/dpop.js:verify",
        "lib/auth/status-list.js:_fromB64url",
        "lib/auth/fido-mds3.js:_b64urlDecode",
        "lib/auth/fido-mds3.js:_parseJws",
        "lib/auth/fido-mds3.js:_verifyJws",
        "lib/auth/fido-mds3.js:_verifyJws",
        "lib/auth/fido-mds3.js:_verifyParamsForAlg",
        "lib/auth/fido-mds3.js:fetch",
        "lib/auth/fido-mds3.js:verifyAuthenticator",
        "lib/auth/dpop.js:buildProof",
        "lib/auth/jwt-external.js:_fetchJwks",
        "lib/network-smtp-policy.js:tlsRptParseReport",
      ],
      reason: "auth-jwt / JOSE family — all five files implement JWS decode + signature verification against operator-supplied or proof-embedded keys. The shared shingle is the canonical 3-part split + base64url decode + safeJson.parse(header/payload) + algorithm allowlist enforcement that every JWS verifier must perform; the divergence is which keys / algorithms / claim-checks each module accepts (PQC algs in jwt.js; classical algs + JWKS in jwt-external.js; full OAuth-discovery + ID-token shape in oauth.js; embedded-jwk DPoP proof in dpop.js with htm/htu/ath/jti claims). Each module's failure-mode codespace (auth-jwt/* vs auth-jwt-external/* vs auth-oauth/* vs auth-dpop/*) is operator-distinguishable so consolidating to a single helper would either lose the distinct error class or pass the class through every helper site. Future consolidation candidate when the JOSE family doubles in size.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/guard-csv.js:compliancePosture",
        "lib/guard-csv.js:detect",
        "lib/guard-csv.js:gate",
        "lib/guard-html.js:_permissiveAllowed",
        "lib/guard-html.js:compliancePosture",
        "lib/guard-html.js:gate",
        "lib/guard-html.js:sanitize",
        "lib/guard-svg.js:<top>",
        "lib/guard-svg.js:_detectIssues",
        "lib/guard-svg.js:compliancePosture",
        "lib/guard-svg.js:gate",
        "lib/guard-svg.js:sanitize",
        "lib/guard-filename.js:<top>",
        "lib/guard-filename.js:gate",
        "lib/guard-filename.js:sanitize",
        "lib/guard-archive.js:<top>",
        "lib/guard-archive.js:_detectIssues",
        "lib/guard-archive.js:gate",
        "lib/guard-archive.js:validateEntries",
        "lib/guard-json.js:<top>",
        "lib/guard-json.js:_detectIssues",
        "lib/guard-json.js:_policyKeyForRuleId",
        "lib/guard-json.js:_scanRawSource",
        "lib/guard-json.js:compliancePosture",
        "lib/guard-json.js:gate",
        "lib/guard-json.js:validate",
        "lib/guard-yaml.js:<top>",
        "lib/guard-yaml.js:_detectIssues",
        "lib/guard-yaml.js:compliancePosture",
        "lib/guard-yaml.js:gate",
        "lib/guard-yaml.js:parse",
        "lib/guard-yaml.js:validate",
        "lib/guard-xml.js:<top>",
        "lib/guard-xml.js:_detectIssues",
        "lib/guard-xml.js:_resolveOpts",
        "lib/guard-xml.js:compliancePosture",
        "lib/guard-xml.js:gate",
        "lib/guard-xml.js:sanitize",
        "lib/guard-xml.js:validate",
        "lib/guard-markdown.js:_detectIssues",
        "lib/guard-markdown.js:_isDangerousUrl",
        "lib/guard-markdown.js:gate",
        "lib/guard-markdown.js:sanitize",
        "lib/guard-markdown.js:validate",
        "lib/guard-email.js:_detectAddressIssues",
        "lib/guard-email.js:_detectMessageIssues",
        "lib/guard-email.js:_parseAddressLine",
        "lib/guard-email.js:_resolveOpts",
        "lib/guard-email.js:gate",
        "lib/guard-email.js:sanitize",
        "lib/guard-domain.js:_resolveOpts",
        "lib/guard-domain.js:_shannonEntropy",
        "lib/guard-domain.js:compliancePosture",
        "lib/guard-domain.js:gate",
        "lib/guard-domain.js:sanitize",
        "lib/guard-domain.js:validate",
        "lib/guard-uuid.js:<top>",
        "lib/guard-uuid.js:_detectIssues",
        "lib/guard-uuid.js:_toCanonicalHex",
        "lib/guard-uuid.js:compliancePosture",
        "lib/guard-uuid.js:gate",
        "lib/guard-uuid.js:sanitize",
        "lib/guard-uuid.js:validate",
        "lib/guard-cidr.js:_detectIssues",
        "lib/guard-cidr.js:_ipv4ToUint32",
        "lib/guard-cidr.js:_ipv6InReservedRange",
        "lib/guard-cidr.js:compliancePosture",
        "lib/guard-cidr.js:gate",
        "lib/guard-cidr.js:sanitize",
        "lib/guard-cidr.js:validate",
        "lib/guard-time.js:<top>",
        "lib/guard-time.js:_detectIssues",
        "lib/guard-time.js:_resolveOpts",
        "lib/guard-time.js:compliancePosture",
        "lib/guard-time.js:gate",
        "lib/guard-time.js:sanitize",
        "lib/guard-time.js:validate",
        "lib/guard-mime.js:<top>",
        "lib/guard-mime.js:_detectIssues",
        "lib/guard-mime.js:_splitTopLevel",
        "lib/guard-mime.js:compliancePosture",
        "lib/guard-mime.js:gate",
        "lib/guard-mime.js:sanitize",
        "lib/guard-mime.js:validate",
        "lib/guard-jwt.js:_b64urlDecodeJson",
        "lib/guard-jwt.js:_detectIssues",
        "lib/guard-jwt.js:_resolveOpts",
        "lib/guard-jwt.js:gate",
        "lib/guard-jwt.js:sanitize",
        "lib/guard-jwt.js:validate",
        "lib/guard-oauth.js:<top>",
        "lib/guard-oauth.js:_resolveOpts",
        "lib/guard-oauth.js:gate",
        "lib/guard-oauth.js:sanitize",
        "lib/guard-graphql.js:<top>",
        "lib/guard-graphql.js:_detectIssues",
        "lib/guard-graphql.js:_measureQueryShape",
        "lib/guard-graphql.js:gate",
        "lib/guard-graphql.js:sanitize",
        "lib/guard-shell.js:<top>",
        "lib/guard-shell.js:_detectIssues",
        "lib/guard-shell.js:_resolveOpts",
        "lib/guard-shell.js:compliancePosture",
        "lib/guard-shell.js:gate",
        "lib/guard-shell.js:sanitize",
        "lib/guard-shell.js:validate",
        "lib/guard-regex.js:<top>",
        "lib/guard-regex.js:_detectIssues",
        "lib/guard-regex.js:_resolveOpts",
        "lib/guard-regex.js:compliancePosture",
        "lib/guard-regex.js:gate",
        "lib/guard-regex.js:sanitize",
        "lib/guard-regex.js:validate",
        "lib/guard-jsonpath.js:<top>",
        "lib/guard-jsonpath.js:_detectIssues",
        "lib/guard-jsonpath.js:_hasDynamicHint",
        "lib/guard-jsonpath.js:compliancePosture",
        "lib/guard-jsonpath.js:gate",
        "lib/guard-jsonpath.js:sanitize",
        "lib/guard-jsonpath.js:validate",
        "lib/guard-template.js:<top>",
        "lib/guard-template.js:_detectIssues",
        "lib/guard-template.js:_resolveOpts",
        "lib/guard-template.js:compliancePosture",
        "lib/guard-template.js:gate",
        "lib/guard-template.js:sanitize",
        "lib/guard-template.js:validate",
        "lib/guard-image.js:<top>",
        "lib/guard-image.js:_detectIssues",
        "lib/guard-image.js:_detectMagicMimes",
        "lib/guard-image.js:gate",
        "lib/guard-image.js:sanitize",
        "lib/guard-pdf.js:<top>",
        "lib/guard-pdf.js:_detectIssues",
        "lib/guard-pdf.js:_hasPdfMagic",
        "lib/guard-pdf.js:gate",
        "lib/guard-pdf.js:sanitize",
        "lib/guard-auth.js:<top>",
        "lib/guard-auth.js:gate",
        "lib/guard-auth.js:sanitize",
        "lib/guard-auth.js:validate",
        "lib/guard-smtp-command.js:<top>",
        "lib/guard-smtp-command.js:gate",
        "lib/guard-smtp-command.js:validate",
        "lib/guard-envelope.js:<top>",
        "lib/guard-envelope.js:check",
      ],
      reason: "guard-* family ABI — every member's gate() factory header (function gate(opts) { opts = _resolveOpts(opts); return gateContract.buildGuardGate(...); }), bottom-of-file helper triplet (buildProfile = gateContract.makeProfileBuilder(PROFILES); function compliancePosture(name) { return gateContract.lookupCompliancePosture(...); }; var _xRulePacks = gateContract.makeRulePackLoader(...); var loadRulePack = _xRulePacks.load), and PROFILES literal block all share the family-shared vocabulary by design. The keys ARE the family contract; the values diverge per guard (csv handles operatorRules + sanitize re-emit; html has sanitize-eligibility branching; svg refuses SVGZ; filename operates on strings; archive on entries; json on parsed trees + source scan). Further extraction would either pull body decision logic that's genuinely per-guard into a shared place, or extract a one-line factory that hides the family contract from anyone reading the guard source.",
    },
    {
      // v0.9.37 — guard-dsn / guard-mail-move / guard-smtp-command
      // share the same module-header scaffolding: lazyRequire +
      // defineClass + PROFILES + COMPLIANCE_POSTURES freeze blocks
      // at <top> of file. Family contract.
      mode:  "family-subset",
      files: [
        "lib/guard-dsn.js:<top>",
        "lib/guard-mail-move.js:<top>",
        "lib/guard-smtp-command.js:<top>",
      ],
      reason: "Module-header scaffolding shared across the guard family — defineClass + lazyRequire + PROFILES freeze + COMPLIANCE_POSTURES freeze blocks. The <top> shape IS the guard-family ABI; consolidating would erase per-guard error-class wrappers + profile vocab.",
    },
    {
      // v0.9.44 — three independently-domain'd entry-points share
      // an array-walk + per-item validation cascade token shape
      // (sd-jwt-vc-issuer.create walks operator-supplied claims;
      // guard-saga-config.validate walks the saga step list;
      // composePipeline walks the middleware-entry array).
      mode:  "family-subset",
      files: [
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/guard-saga-config.js:validate",
        "lib/middleware/compose-pipeline.js:composePipeline",
      ],
      reason: "Three independently-domain'd entry points share an array-walk + per-item validation cascade. Each emits a domain-distinct error class (SdJwtVcIssuerError / GuardSagaConfigError / ComposePipelineError) and validates a different field tuple. Consolidating would couple unrelated specs.",
    },
    {
      // v0.9.40 — RFC 5322 header-injection control-char scans
      // (boolean variant: does this string contain CR/LF/NUL/C0/DEL?)
      // inlined in 4 guards. Each is a 8-line for-loop with a fixed
      // charCodeAt + range-check structure. The detector matches
      // because the shape IS the contract; extracting to a shared
      // helper saves ~25 lines but adds a module-boundary import +
      // a runtime call per check.
      mode:  "family-subset",
      files: [
        "lib/guard-dsn.js:_checkControlChars",
        "lib/guard-list-id.js:_hasControlChar",
        "lib/guard-list-unsubscribe.js:_hasControlChar",
        "lib/safe-redirect.js:_hasControlChar",
      ],
      reason: "RFC 5322 header-injection boolean scan (CR/LF/NUL/C0/DEL char-code check, allow TAB). Each guard inlines an 8-line for-loop; the shape IS the contract. Future consolidation candidate via `lib/codepoint-class.js` if the family grows past 5 sites, but the per-guard scan keeps the error-class wrapper (GuardDsnError / GuardListIdError / GuardListUnsubscribeError / SafeRedirectError) domain-local and the inlined check has zero call overhead.",
    },
    {
      // v0.9.39 — three independently-domain'd helper bodies
      // (guardListUnsubscribe._verdict assembling the action+reason
      // payload, guardSmtpCommand._validateAuth walking AUTH mech
      // shape, safeDns._decodeOpt walking EDNS0 OPT pseudo-RR)
      // happen to share the local-var / return-shape token sequence
      // the detector matches. Each has a domain-distinct body.
      mode:  "family-subset",
      files: [
        "lib/guard-list-id.js:_refuse",
        "lib/guard-list-unsubscribe.js:_verdict",
        "lib/guard-smtp-command.js:_parseAuthCommandSyntax",
        "lib/safe-dns.js:_decodeOpt",
      ],
      reason: "Three independently-domain'd helpers (List-Unsubscribe verdict assembly / SMTP AUTH mech validation / DNS OPT pseudo-RR decode) share local-var declaration + return-shape token sequence. Bodies are domain-distinct (different field names, different error checks). Consolidation would couple unrelated parsers.",
    },
    {
      // v0.9.37 — guard-dsn / guard-smtp-command / safe-dns all
      // declare the same _resolveProfile dispatcher mapping operator
      // opts → PROFILES[caps] with the COMPLIANCE_POSTURES cascade.
      // The dispatcher IS the family contract.
      mode:  "family-subset",
      files: [
        "lib/guard-dsn.js:_resolveProfile",
        "lib/guard-list-id.js:_resolveProfile",
        "lib/guard-list-unsubscribe.js:_resolveProfile",
        "lib/guard-smtp-command.js:_resolveProfile",
        "lib/safe-dns.js:_resolveProfile",
      ],
      reason: "_resolveProfile dispatcher — every safe-* / guard-* primitive walks the same `opts.posture → COMPLIANCE_POSTURES[posture] → PROFILES[caps]` cascade with `opts.profile` fallback. The cascade IS the family ABI; consolidating to a shared helper would erase the per-primitive error-class wrapper (SafeDnsError / GuardDsnError / GuardSmtpCommandError) that operator audit pipelines route on.",
    },
    {
      // v0.9.33 — mailRbl.query / queryDomain share the
      // required-non-empty-string prelude with OAuth callback parser
      // + DDL hash-input validator. Each emits a distinct error class.
      mode:  "family-subset",
      files: [
        "lib/auth/oauth.js:parseCallback",
        "lib/ddl-change-control.js:_hashSql",
        "lib/mail-rbl.js:query",
        "lib/mail-rbl.js:queryDomain",
      ],
      reason: "Two-arg required-non-empty-string validation prelude. OAuth callback parser refuses missing redirect URI / state, DDL change-control hashes the SQL string, mail-rbl rejects empty IP / domain. Each emits a distinct error class (OAuthError / DdlChangeControlError / MailRblError) — consolidation would couple unrelated domain validators.",
    },
    {
      // v0.9.34 — auth/oauth.exchangeToken + sd-jwt-vc-holder.store +
      // backup/index.scheduleTest + mailGreylist.check share a
      // required-args + opts-merge prelude. Each emits a domain-typed
      // error class (OAuthError / SdJwtVcHolderError / BackupError /
      // MailGreylistError) with a different field tuple — consolidating
      // would couple unrelated regulatory specs.
      mode:  "family-subset",
      files: [
        "lib/auth/oauth.js:exchangeToken",
        "lib/auth/sd-jwt-vc-holder.js:store",
        "lib/backup/index.js:scheduleTest",
        "lib/mail-greylist.js:check",
      ],
      reason: "Required-args + opts-merge prelude shared across an OAuth token-exchange call, an SD-JWT VC holder.store, a backup-test scheduler, and the greylist .check input gate. Each domain emits a distinct error class with a different field tuple; consolidation would couple unrelated specs.",
    },
    {
      files: [
        "lib/api-snapshot.js:write",
        "lib/break-glass.js:unsealRowAsService",
        "lib/deprecate.js:alias",
      ],
      reason: "Two-arg required-string validation pattern — different domains coincidentally share the `if (!opts || typeof opts !== 'object') ... if (typeof X !== 'string' || X.length === 0)` shape. Sites use file-specific error classes that diverge from the framework standard signature.",
    },
    {
      files: ["lib/atomic-file.js:copyDirRecursive", "lib/deprecate.js:alias", "lib/totp.js:uri"],
      reason: "Two consecutive non-empty-string checks. Sites use AtomicFileError / DeprecateError / TotpError — each with a slightly different constructor signature that doesn't fit requireNonEmptyString. Tracked for future error-class-signature normalization.",
    },
    {
      files: [
        "lib/audit-chain.js:verifyChain",
        "lib/audit-tools.js:_verifyChainSlice",
        "lib/audit.js:verifyCheckpoints",
      ],
      reason: "Audit chain verification loop — `for (var i ...) { if (entry.X !== expected) return { ok: false, ...}}`. Inherent to the audit verification domain; the loop body checks domain-specific invariants.",
    },
    {
      files: [
        "lib/audit-sign.js:init",
        "lib/framework-schema.js:ensureSchema",
        "lib/vault/index.js:init",
      ],
      reason: "PQC envelope-validation entry shape — `if (!X || !X.field) throw; var alg = (X.alg || '').toLowerCase(); if (alg !== 'A' && alg !== 'B') throw`. Each module checks its own envelope contract.",
    },
    {
      files: [
        "lib/auth/jwt.js:_requireNumericDate",
        "lib/external-db.js:_requirePosInt",
        "lib/http-client.js:_requirePositiveInt",
      ],
      reason: "Optional-field forwarder pattern — `if (X.A !== undefined) emit('A', X.A); if (X.B !== undefined) emit('B', X.B)`. Each module's emit-specific (jwt claims / db pool stats / http headers).",
    },
    {
      files: [
        "lib/backup/bundle.js:<unknown>",
        "lib/restore-bundle.js:<unknown>",
        "lib/restore-rollback.js:<unknown>",
      ],
      reason: "Bundle file-IO entry — `if (typeof opts.X !== 'string' || !atomicFile.Y(opts.X)) throw; atomicFile.Z(opts.X, ...)`. Backup/restore lifecycle ops share file-validation entry shape; refactoring would consolidate into a backup/restore base helper. Tracked as future opportunity.",
    },
    {
      files: [
        "lib/backup/bundle.js:create",
        "lib/restore-bundle.js:extract",
        "lib/vault/rotate.js:rotate",
      ],
      reason: "Same backup/restore/vault file-IO pattern as above; vault/rotate participates because it uses the same bundle wrapping. Future consolidation candidate.",
    },
    {
      files: [
        "lib/backup/index.js:_emitAudit",
        "lib/restore.js:_emitAudit",
        "lib/scheduler.js:_emit",
      ],
      reason: "Async timer setup with cleanup — `setInterval` + `unref()` + `cancel()` shape. Scheduler-shape primitives across backup / restore / scheduler. Three different operator-facing primitives with different timer semantics; consolidation candidate but each has distinct cleanup contract.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/jwt-external.js:_fetchJwks",
        "lib/auth/jwt-external.js:verifyExternal",
        "lib/auth/oauth.js:_postForm",
        "lib/auth/oauth.js:verifyIdToken",
        "lib/network-smtp-policy.js:tlsRptFetchPolicy",
        "lib/network-smtp-policy.js:tlsRptParseReport",
        "lib/mail-auth.js:_fetchDmarcRecord",
        "lib/mail-auth.js:_fetchSpfRecord",
        "lib/mail-auth.js:dmarcParseAggregateReport",
        "lib/mail-bimi.js:fetchPolicy",
      ],
      reason: "External structured-data ingestion + safe-* parser + file-specific framework-error throw. Each module ingests serialized data from a different external surface (JWKS endpoint over HTTP, OAuth discovery doc, TLS-RPT JSON report, DMARC RUA XML report, BIMI TXT record) with file-specific size caps and error classes. Extracting to a shared helper would either lose the per-module error class or pass it through every helper site, making the call sites less readable than the current inline 3-line block.",
    },
    {
      files: [
        "lib/db-declare-row-policy.js:_validateOpts",
        "lib/db-declare-view.js:_validateOpts",
        "lib/middleware/db-role-for.js:create",
      ],
      reason: "Role/policy SQL identifier validation + dbRole compound check. Three different declarative-DB primitives share the role-name validation entry. Future consolidation candidate as `db.validateRoleSpec(opts, errorClass, code)`.",
    },
    {
      files: ["lib/dual-control.js:request", "lib/notify.js:send", "lib/retention.js:_validateRule"],
      reason: "Required + nested-shape validation — `async function f(opts) { if (!opts || typeof opts !== 'object') throw; if (typeof opts.X !== 'string' || opts.X.field === N) throw }`. Each primitive's specific contract on opts.X varies (purpose / channel / table); compound shape resists generic extraction.",
    },
    {
      files: [
        "lib/external-db-migrate.js:_loadMigration",
        "lib/migrations.js:_loadMigration",
        "lib/seeders.js:_loadSeed",
      ],
      reason: "Migration runner file-listing + apply pattern. The dbSchema.runInTransaction extraction handled the BEGIN/COMMIT/ROLLBACK; what remains is the file-loading + each-file-apply loop. Inherent to migration-runner domain; each runner has slightly different metadata / environment shape.",
    },
    {
      files: [
        "lib/html-balance.js:<unknown>",
        "lib/object-store/sigv4.js:<unknown>",
        "lib/parsers/safe-xml.js:<unknown>",
      ],
      reason: "Character-class range checks (`(c >= 0xA && c <= 0xZ) || (c >= 0xA2 && c <= 0xZ2)`) appearing in any string-classifier code. Generic JS idiom, not extractable.",
    },
    {
      files: [
        "lib/log-stream-cloudwatch.js:emit",
        "lib/log-stream-otlp.js:emit",
        "lib/log-stream-webhook.js:emit",
      ],
      reason: "Log-stream emit() entry — `} ); if (buffer.length >= cfg.batchSize) { _flush().catch(()=>{}); } else { flushScheduler.schedule(); } return Promise.resolve({ accepted: true, queued: buffer.length });`. The framework's log-stream sinks share this exact emit return shape. Could be a base-factory but each sink's surrounding emit-pre-checks differ.",
    },
    {
      files: [
        "lib/mail-dkim.js:<unknown>",
        "lib/metrics.js:<unknown>",
        "lib/safe-schema.js:<unknown>",
      ],
      reason: "Format-array iteration with predicate check — `for (var i ...) { if (!predicate(arr[i])) throw }`. Generic JS validation pattern across unrelated domains.",
    },
    {
      files: [
        "lib/auth/access-lock.js:create",
        "lib/auth/fido-mds3.js:_validateChain",
        "lib/config.js:create",
        "lib/mail-dkim.js:create",
        "lib/middleware/require-bound-key.js:create",
      ],
      reason: "Operator-supplied string-array validation prelude — `Array.isArray(opts.X) ? opts.X.slice() : [] + for-loop with typeof !== string check throwing per-domain error class`. Five different domains (access-lock unlockRoles / fido-mds3 cert-chain x5c / config primary-keys / mail-dkim selectors / require-bound-key requiredScopes); each loop throws a domain-specific error code on bad entries. Generic shape, not consolidatable.",
    },
    {
      files: [
        "lib/auth/access-lock.js:create",
        "lib/config.js:create",
        "lib/mail-dkim.js:create",
        "lib/middleware/require-bound-key.js:create",
      ],
      reason: "Sub-cluster of the above five-file string-array validation prelude — the 50-token shingle catches the four-way intersection when fido-mds3 doesn't happen to share enough contiguous lines. Same structural reason: four different domains, four different error classes, generic JS validation shape.",
    },
    {
      files: [
        "lib/guard-html.js:_tokenize",
        "lib/guard-svg.js:_tokenize",
        "lib/mail-bimi.js:_tokenizeTinyPsSvg",
      ],
      reason: "HTML/SVG tokenizer family — each walks the same `<` / `<!` / `<?` / `</` / `<!--` / `<![CDATA[` / `<!DOCTYPE` dispatcher chain. guard-html sanitises arbitrary HTML; guard-svg sanitises SVG to a safe subset; mail-bimi validates BIMI Tiny-PS SVG against a STRICTER subset (no scripts, no foreignObject, no animation, no external refs, viewBox required, ≤32 KiB). Each tokenizer's downstream consumer applies a different allowlist + sanitisation policy; consolidating would force one tokenizer with three sanitisation modes and erase per-domain refusal codes (GuardHtmlError / GuardSvgError / MailBimiError).",
    },
    {
      files: [
        "lib/auth/fido-mds3.js:_parseJws",
        "lib/backup/index.js:create",
        "lib/dsr.js:create",
      ],
      reason: "validateOpts + safeJson.parse-with-byte-cap prelude — fido-mds3 parses the JWS BLOB header/payload (capped at 64 KiB header, 32 MiB payload); backup decodes a manifest JSON; dsr decodes the data-subject-request descriptor. Three different domains, three different error classes (FidoMds3Error / BackupError / DsrError); the 50-token shingle is the `safeJson.parse(buf.toString('utf8'), { maxBytes: ... })` entry-point shape.",
    },
    {
      files: [
        "lib/auth/fido-mds3.js:_validateChain",
        "lib/middleware/require-methods.js:create",
        "lib/network-dns.js:useDesignatedResolvers",
      ],
      reason: "Array-of-strings normalisation prelude — `Array.isArray(opts.X) || throw + for-loop typeof !== string check`. fido-mds3 walks the JWS x5c cert chain; require-methods walks the allowed HTTP methods list; network-dns walks the operator-supplied DNS-over-Designated-Resolvers list. Three different per-domain error classes (FidoMds3Error / NetworkDnsError / TypeError) and per-domain content vocabularies.",
    },
    {
      files: [
        "lib/auth/access-lock.js:create",
        "lib/config.js:create",
        "lib/middleware/require-bound-key.js:create",
      ],
      reason: "Same string-array validation prelude as the four-file cluster above; the 60-token shingle catches a slightly larger window than the 50-token one when only three of the four files happen to share contiguous validation+normalization+initial-emit logic. Generic JS shape, three different domains.",
    },
    {
      files: [
        "lib/backup/index.js:_validateStorage",
        "lib/middleware/require-bound-key.js:create",
        "lib/restore.js:_validateStorage",
      ],
      reason: "Async-iteration over operator-supplied collection with try/catch + per-item error mapping — backup walks file entries, restore walks archive entries, require-bound-key walks bound-field getters. Three different domains, three different per-item error vocabularies; consolidating would erode each iterator's domain validation.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/mail-arc-sign.js:sign",
        "lib/mail-dkim.js:create",
        "lib/metrics.js:histogram",
        "lib/safe-schema.js:<unknown>",
      ],
      reason: "Same array-iteration-with-predicate shape as the mail-dkim/metrics/safe-schema cluster — mail-arc-sign's headersToSign element validation walks the operator-supplied array of header names with the same `for (var i ...) { if (!predicate(arr[i])) throw }` shape; predicate body differs per domain.",
    },
    {
      files: [
        "lib/inbox.js:create",
        "lib/middleware/span-http-server.js:create",
        "lib/outbox.js:create",
      ],
      reason: "Transactional-store + span-lifecycle audit prelude — inbox.handle / outbox.relay / span-http-server's response-finish hook each invoke `audit.safeEmit({ action, outcome, metadata })` inside a try/catch swallow on the hot path. Three different domains (dedupe-on-receive vs at-least-once relay vs HTTP request span); the 50-token shingle is the sink-emit shape, not the domain logic.",
    },
    {
      files: ["lib/mail.js:<unknown>", "lib/migrations.js:<unknown>", "lib/seeders.js:<unknown>"],
      reason: "Identifier/format validation + sql identifier check. Mail uses email-address validators; migrations/seeders use SQL identifier validators. Different domains with the same `function isXValid(s) { return typeof s === 'string' && s.length > 0 && s.length <= MAX && regex.test(s); }` shape.",
    },
    {
      files: [
        "lib/middleware/bot-guard.js:<unknown>",
        "lib/middleware/cors.js:<unknown>",
        "lib/middleware/csrf-protect.js:<unknown>",
      ],
      reason: "Middleware factory boilerplate — opts validation + xff/trustProxy parse + helper wiring. Middleware factories share scaffolding by design; consolidating into a base factory would cost more readability than it saves.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/middleware/cookies.js:_emitAudit",
        "lib/middleware/gpc.js:_emitAudit",
        "lib/middleware/headers.js:_emitAudit",
      ],
      reason: "Threat-detection middleware family — each shares the same `_emitAudit(audit, action, outcome, metadata) { ... try { audit.safeEmit({...}); } catch (_e) { /* drop-silent */ } }` audit-emission shape. Per the validation-tier policy this is the hot-path observability sink shape; extracting would force a shared `audit-emit-drop-silent` primitive — the framework already has audit.safeEmit, and the middleware-local wrapper's value is keeping the drop-silent behavior visible at the call site. Future consolidation candidate.",
    },
    {
      files: [
        "lib/middleware/bot-guard.js:_checkHeuristics",
        "lib/middleware/cors.js:create",
        "lib/middleware/rate-limit.js:_writeBlocked",
      ],
      reason: "Same middleware-factory cluster as above with rate-limit substituted. Same justification.",
    },
    {
      files: [
        "lib/middleware/db-role-for.js:<unknown>",
        "lib/notify.js:<unknown>",
        "lib/seeders.js:<unknown>",
        "lib/webhook.js:<unknown>",
      ],
      reason: "Optional-nested-object shape validation — `if (opts.X !== undefined && opts.X !== null) { if (typeof opts.X !== 'object' || typeof opts.X.method !== 'function') throw }`. Each handle has a different method-shape contract (audit / observability / queue / permissions). Future consolidation candidate as `validateOpts.methodShape(value, methodName, label, errorClass)`.",
    },
    {
      files: [
        "lib/middleware/db-role-for.js:<unknown>",
        "lib/seeders.js:<unknown>",
        "lib/webhook.js:<unknown>",
      ],
      reason: "Same nested-shape cluster as above with notify removed. Same justification.",
    },
    {
      files: [
        "lib/network-proxy.js:_emitObs",
        "lib/network-tls.js:_emitObs",
        "lib/network.js:_emitObs",
      ],
      reason: "Network listener teardown shape — `function reset() { state.X = null; state.Y = null; state.Z = []; ...}`. Each network primitive has a different reset surface; consolidating would force unrelated state into a base contract.",
    },
    {
      files: ["lib/notify.js:<unknown>", "lib/seeders.js:<unknown>", "lib/webhook.js:<unknown>"],
      reason: "Same nested-shape cluster as middleware/db-role-for+notify+seeders+webhook (see above) with db-role-for removed.",
    },
    {
      files: [
        "lib/object-store/azure-blob.js:_buildSasToken",
        "lib/object-store/gcs.js:presignedUploadPolicy",
        "lib/object-store/sigv4.js:presignedUploadPolicy",
      ],
      reason: "S3-protocol shared upload shape — multipart-upload state machine fingerprint. Each protocol's upload shape differs in headers / signing / response parsing; common scaffolding (request-helper, response-parse) is already extracted to lib/object-store/http-request.js.",
    },
    {
      files: [
        "lib/object-store/azure-blob.js:head",
        "lib/object-store/http-put.js:head",
        "lib/object-store/sigv4.js:head",
      ],
      reason: "Same object-store SDK cluster as above with http-put substituted. Same justification.",
    },
    {
      files: [
        "lib/object-store/gcs.js:<unknown>",
        "lib/object-store/sigv4.js:<unknown>",
        "lib/static.js:<unknown>",
      ],
      reason: "Operator-supplied URL parsing entry — `var parsed = safeUrl.parse(url, { ... }); var hostname = parsed.hostname; ...`. URL extraction shape across object-store backends + static-asset server.",
    },
    {
      files: [
        "lib/parsers/safe-env.js:parse",
        "lib/parsers/safe-toml.js:parse",
        "lib/parsers/safe-yaml.js:parse",
      ],
      reason: "Parser entry — `function parse(input, opts) { opts = opts || {}; if (opts.maxBytes !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxBytes)) throw }`. Parser error classes use `(message, code, line, col)` constructor signature that doesn't fit numericBounds.requireXIfPresent helper. Future opportunity: normalize parser error class signatures to match framework standard.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/audit-daily-review.js:create",
        "lib/cloud-events.js:wrap",
        "lib/ddl-change-control.js:create",
        "lib/external-db-migrate.js:create",
        "lib/fda-21cfr11.js:posture",
        "lib/fdx.js:consentReceipt",
        "lib/file-upload.js:_validateCreateOpts",
        "lib/redact.js:installOutboundDlp",
        "lib/sec-cyber.js:eightKArtifact",
        "lib/static.js:_validateCreateOpts",
      ],
      reason: "validateOpts factory + JSON-envelope scaffolding family — each primitive's create() runs `validateOpts(opts, ALLOWED_KEYS, label) + validateOpts.requireObject(...) + validateOpts.requireNonEmptyString(...) + validateOpts.optionalY(...)` then assembles its domain-specific config. Ten different domains (compliance daily review / CloudEvents wrapper / DDL change-control / external-db migration / 21 CFR Part 11 / FDX consent / file-upload validation / outbound DLP / SEC 8-K artifact / static-serve validation); each emits a different error class and a different opts vocabulary. Consolidating the prelude past the call boundary would surface the wrong error code for operator typos.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/ai-adverse-decision.js:wrap",
        "lib/audit-daily-review.js:create",
        "lib/cloud-events.js:wrap",
        "lib/ddl-change-control.js:create",
        "lib/external-db-migrate.js:create",
        "lib/fda-21cfr11.js:posture",
        "lib/observability-tracer.js:create",
        "lib/redact.js:installOutboundDlp",
      ],
      reason: "Observability-emit + validateOpts prelude family — each primitive opens with the validateOpts cascade then attaches an observability.event call (tracer span / decision audit / DDL approval / migration / 21 CFR signature / DLP scan). Eight different domains; consolidating would force a single emit shape and lose per-primitive event-name conventions.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/audit-daily-review.js:create",
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/external-db-migrate.js:create",
        "lib/fda-21cfr11.js:posture",
        "lib/fdx.js:consentReceipt",
        "lib/middleware/db-role-for.js:create",
        "lib/middleware/dpop.js:create",
        "lib/middleware/tus-upload.js:create",
        "lib/outbox.js:create",
        "lib/static.js:_validateCreateOpts",
        "lib/vault/seal-pem-file.js:sealPemFile",
      ],
      reason: "Factory-create() opts-resolution scaffolding family — `var X = applyDefaults(opts, DEFAULTS); validateOpts.optionalY(...); validateOpts.optionalZ(...)` cascades. Eleven different domains (daily review / sanctions fetcher / migration / 21 CFR / FDX / db-role middleware / DPoP / TUS / outbox / static / sealed-PEM); each closure captures a different downstream binding. Same factory-prelude convention as the JSON-envelope cluster above; tracked separately because the file-set varies.",
    },
    {
      files: [
        "lib/auth/sd-jwt-vc-holder.js:_emitAudit",
        "lib/auth/sd-jwt-vc-issuer.js:_emitAudit",
        "lib/compliance-sanctions-fetcher.js:_emitAudit",
        "lib/compliance-sanctions.js:_emitAudit",
        "lib/outbox.js:_emitAudit",
        "lib/tenant-quota.js:_emitAudit",
      ],
      reason: "_emitAudit drop-silent helper family — each primitive defines a local `_emitAudit(action, info) { try { audit.safeEmit({ action: action, ...info }); } catch (_e) { /* drop-silent */ } }`. Per the validation-tier policy this is the hot-path observability sink shape; the framework already exposes validateOpts.makeAuditEmitter for the no-arg form, but these sites emit bound action namespaces (`sdjwt.vc.holder.*`, `sanctions.fetcher.*`, `outbox.*`, `tenant.quota.*`) that the call-site closure captures.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/sd-jwt-vc-issuer.js:create",
        "lib/break-glass.js:_validatePolicySet",
        "lib/compliance-eaa.js:create",
        "lib/db.js:declareRequireDualControl",
        "lib/dsr.js:create",
        "lib/middleware/assetlinks.js:create",
        "lib/network-heartbeat.js:start",
      ],
      reason: "validateOpts.requireNonEmptyString + optionalNonEmptyStringArray prelude family — every entry-point opens with the same required-string + optional-string-array check cascade because the caller-supplied opts share the typo-handling convention. Seven different domains and seven different error classes (SdJwtVcError / BreakGlassError / EaaError / DbError / DsrError / FrameworkError / HeartbeatError); consolidating past the call boundary would surface the wrong error code for operator typos.",
    },
    {
      files: [
        "lib/auth/sd-jwt-vc-holder.js:store",
        "lib/compliance-sanctions.js:screen",
        "lib/dora.js:_validateReportInput",
        "lib/fda-21cfr11.js:_validateSignatureInput",
        "lib/incident-report.js:open",
      ],
      reason: "Operator-input validation scaffolding shape — `validateOpts.requireObject(input, label, ErrClass); validateOpts.requireNonEmptyString(input.X, ...); validateOpts.requireNonEmptyString(input.Y, ...);` then domain-specific shape checks. Six different domains (DPoP JWK canonicalize / SD-JWT VC store / sanctions screening / DORA report shape / 21 CFR signature / incident-report open); consolidating would force a shared input-validator that the per-domain error class signatures don't fit.",
    },
    {
      files: [
        "lib/http-message-signature.js:_parseSignatureInput",
        "lib/mail-auth.js:_parseDmarcRecord",
        "lib/mail-bimi.js:parseRecord",
        "lib/mail-dkim.js:_parseDkimTagList",
        "lib/network-smtp-policy.js:_parseStsPolicy",
      ],
      reason: "Header / TXT-record tag-list parser family — each parses its own RFC-defined `tag=value; tag=value` structure (RFC 9421 signature-input / RFC 7489 DMARC / RFC 9165 BIMI / RFC 6376 DKIM / RFC 8461 MTA-STS). Consolidating would erase per-RFC tag-quoting and continuation-line rules; the 60-token shingle is the loop-and-split skeleton.",
    },
    {
      files: [
        "lib/auth/password.js:check",
        "lib/http-message-signature.js:_parseSignatureInput",
        "lib/middleware/tus-upload.js:_parseMetadata",
        "lib/observability.js:_parseBaggage",
        "lib/observability.js:_parseTracestate",
        "lib/request-helpers.js:parseQualityList",
      ],
      reason: "key=value / key value parser pair family — Argon2id PHC + RFC 9421 signature-input + TUS Upload-Metadata + W3C baggage + W3C tracestate + RFC 7231 quality-list each independently iterate over key=value tokens splitting on the first separator. Same scaffolding noted in the existing parseQualityList cluster (line 1727); listed again because the file-set differs (sd-jwt-vc-issuer / sanctions screening interactions push fp to a new cluster).",
    },
    {
      files: [
        "lib/auth/password.js:check",
        "lib/http-message-signature.js:_parseSignatureInput",
        "lib/observability.js:_parseBaggage",
        "lib/observability.js:_parseTracestate",
      ],
      reason: "Same key=value parser family as above with TUS / quality-list removed. Same justification.",
    },
    {
      files: [
        "lib/atomic-file.js:copyDirRecursive",
        "lib/ddl-change-control.js:approve",
        "lib/ddl-change-control.js:reject",
        "lib/deprecate.js:alias",
        "lib/totp.js:uri",
      ],
      reason: "String-format builder shape — `var X = String(arg); if (typeof X !== 'string' || X.length === 0) throw; return X.replace(/.../g, ...) + '...' + Y;`. Atomic-file recursive copy / DDL approve+reject audit-trail / deprecation alias announcer / TOTP otpauth URI construction; five different domains, five different output formats. Tracked together because the validation+concat skeleton shingles.",
    },
    {
      files: [
        "lib/atomic-file.js:copyDirRecursive",
        "lib/ddl-change-control.js:reject",
        "lib/totp.js:uri",
      ],
      reason: "Same string-format builder family as above with the DDL approve + deprecate.alias sites removed. Same justification.",
    },
    {
      files: [
        "lib/auth-bot-challenge.js:create",
        "lib/auth/jwt.js:_requireNumericDate",
        "lib/external-db.js:_requirePosInt",
        "lib/http-client.js:_requirePositiveInt",
      ],
      reason: "Per-primitive `_requireXxx(value, label)` numeric-validator helpers — each module rolls a small `function _requirePositiveInt(v, label) { if (typeof v !== 'number' || ...) throw new XError(...); return v; }` because numericBounds throws plain TypeError that doesn't fit per-domain error classes. Future consolidation candidate as numericBounds.requirePositiveIntAs(value, label, errorClass, code).",
    },
    {
      files: [
        "lib/db-declare-row-policy.js:_validateOpts",
        "lib/db-declare-view.js:_validateOpts",
        "lib/legal-hold.js:place",
        "lib/middleware/db-role-for.js:create",
      ],
      reason: "DB-declare opts-validation scaffolding — `validateOpts.requireObject(opts, ...); validateOpts.requireNonEmptyString(opts.tableName, ..., DbError, code); validateOpts.requireNonEmptyString(opts.X, ..., DbError, code);`. Four different db-declare entry points (row-policy / view / legal-hold place / db-role middleware); each emits a different error code on operator typo. Consolidating would lose the per-call code.",
    },
    {
      files: [
        "lib/db-declare-row-policy.js:_validateOpts",
        "lib/db-declare-view.js:_validateOpts",
        "lib/legal-hold.js:place",
      ],
      reason: "Same DB-declare opts-validation cluster as above with the db-role-for middleware site removed. Same justification.",
    },
    {
      files: [
        "lib/auth/sd-jwt-vc-holder.js:store",
        "lib/backup/index.js:scheduleTest",
        "lib/fda-21cfr11.js:_validateSignatureInput",
        "lib/incident-report.js:open",
      ],
      reason: "Operator-supplied record validation shape — each entry runs `validateOpts.requireObject(input, ...); validateOpts.requireNonEmptyString(input.id, ...); validateOpts.optionalNonEmptyString(input.metadata, ...);` then writes a row through db.from(). Four different domains (SD-JWT VC store / backup test schedule / 21 CFR signature / incident-report); each db row has a different schema.",
    },
    {
      files: [
        "lib/auth/sd-jwt-vc-holder.js:store",
        "lib/fda-21cfr11.js:_validateSignatureInput",
        "lib/incident-report.js:open",
      ],
      reason: "Same operator-supplied record validation cluster as above with the backup-scheduleTest site removed. Same justification.",
    },
    {
      files: [
        "lib/auth/dpop.js:verify",
        "lib/backup/index.js:scheduleTest",
        "lib/break-glass.js:_validatePolicySet",
        "lib/ddl-change-control.js:propose",
      ],
      reason: "Multi-step verification scaffold — `validateOpts.requireObject(...); var X = validateOpts.requireNonEmptyString(...); var Y = validateOpts.optionalNonEmptyString(...); ...; if (cond) throw new XError(...)`. DPoP proof verify / backup scheduleTest / break-glass policy validation / DDL change-control propose. Four different domains, four different validation rules.",
    },
    {
      files: [
        "lib/auth/dpop.js:verify",
        "lib/backup/index.js:scheduleTest",
        "lib/break-glass.js:_validatePolicySet",
      ],
      reason: "Same multi-step verification cluster as above with the DDL-propose site removed. Same justification.",
    },
    {
      files: [
        "lib/asyncapi.js:parse",
        "lib/backup/manifest.js:validate",
        "lib/openapi.js:parse",
      ],
      reason: "Schema-document parser entry — `function parse(input, opts) { opts = opts || {}; validateOpts.requireObject(input, ...); ... if (input.X === undefined) throw }`. AsyncAPI / OpenAPI parser + backup manifest validator share validation scaffolding because each is a structured-document parser with required top-level fields. Three different schemas (AsyncAPI 3.0 / OpenAPI 3.1 / blamejs backup manifest); consolidating would force a shared schema-walker.",
    },
    {
      files: [
        "lib/auth-bot-challenge.js:_safeGlobalObs",
        "lib/auth/lockout.js:_safeGlobalObs",
        "lib/session-device-binding.js:_safeGlobalObs",
      ],
      reason: "_safeGlobalObs drop-silent observability helper — each primitive defines a local `function _safeGlobalObs(action, attrs) { try { observability.event({...}); } catch (_e) { /* drop-silent */ } }` because the global observability binding is module-load-time captured. Three auth-related primitives; the closure captures the per-primitive event-name namespace. Same observability-sink discipline noted in the cookies/gpc/headers _emitAudit cluster.",
    },
    {
      files: [
        "lib/db-query.js:<top>",
        "lib/db.js:init",
        "lib/db.js:stream",
        "lib/external-db.js:_connectAs",
      ],
      reason: "node:sqlite + external-db wiring scaffold — `var statement = database.prepare('...'); var rows = statement.all(...); for (i in rows) { ... }`. db-query top-level statement-cache setup, db.init schema-bootstrap walk, db.stream readable-walk, external-db.js role connect-as walk. Four sites within the db / external-db domain; the SQL bodies and result shapes differ per call.",
    },
    {
      files: [
        "lib/dual-control.js:create",
        "lib/legal-hold.js:create",
        "lib/retention.js:create",
      ],
      reason: "Compliance-gate primitive create() factory — `function create(opts) { opts = opts || {}; validateOpts.requireObject(opts, ...); var audit = validateOpts.auditShape(opts.audit, ...); var _emit = validateOpts.makeAuditEmitter(audit); ... return { check, place, release, list }; }`. Three different compliance gates (m-of-n dual-control / legal-hold / retention); each return-shape exposes a different operator-facing surface. Consolidating into a base would couple unrelated primitives.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/external-db-migrate.js:create",
        "lib/fda-21cfr11.js:posture",
        "lib/outbox.js:create",
      ],
      reason: "Subset of the outbox / 21 CFR / external-db-migrate factory cluster covered above. Tracked separately because the 60-token shingle drops below the 5-file threshold once the middleware-dpop / static / vault sites are removed.",
    },
    {
      // [fp:c623e683e98d / fp:c5467f38cecc / fp:3831ac4d1b6a / fp:404308d797b1 / fp:8854d4482747]
      mode:  "family-subset",
      files: [
        "lib/ai-adverse-decision.js:_emitAudit",
        "lib/auth/access-lock.js:_emitAudit",
        "lib/breach-deadline.js:_emitAudit",
        "lib/compliance-eaa.js:_emitAudit",
        "lib/compliance-sanctions.js:_emitAudit",
        "lib/cra-report.js:_emitAudit",
        "lib/dsr.js:_emitAudit",
        "lib/gdpr-ropa.js:_emitAudit",
        "lib/incident-report.js:_emitAudit",
        "lib/middleware/age-gate.js:_emitAudit",
        "lib/middleware/daily-byte-quota.js:_emitAudit",
        "lib/network-byte-quota.js:_emitAudit",
        "lib/nis2-report.js:_emitAudit",
        "lib/observability-otlp-exporter.js:_emitAudit",
        "lib/vault/seal-pem-file.js:_emitAudit",
      ],
      reason: "Network-byte-quota + observability-otlp-exporter extension of the audit + observability emit prelude family already documented above. Each primitive defines a local _emitAudit(action, info) {  try { audit().safeEmit({ action, outcome, metadata }); } catch (_e) { /* drop-silent */ } } shape per the validation-tier policy (drop-silent at hot-path observability sinks). Different action vocabularies (decision.* / accesslock.* / breach.* / dailyquota.* / netquota.* / otlp.export.*) capture per-domain audit namespaces; consolidating would lose the per-primitive metric name.",
    },
    {
      // [fp:b633c0ceaaec / fp:579898bab7df / fp:d5f756a0ac58 / fp:7f568db6d632 / fp:99572742f969 / fp:daf3cde558d6]
      mode:  "family-subset",
      files: [
        "lib/audit-daily-review.js:create",
        "lib/cloud-events.js:wrap",
        "lib/daemon.js:_validateStartOpts",
        "lib/daemon.js:_validateStopOpts",
        "lib/ddl-change-control.js:create",
        "lib/external-db-migrate.js:create",
        "lib/fda-21cfr11.js:posture",
        "lib/fdx.js:consentReceipt",
        "lib/file-upload.js:_validateCreateOpts",
        "lib/redact.js:installOutboundDlp",
        "lib/sec-cyber.js:eightKArtifact",
        "lib/self-update.js:_validateVerifyOpts",
        "lib/static.js:_validateCreateOpts",
      ],
      reason: "Daemon + self-update extension of the validateOpts factory + JSON-envelope cluster documented above. Each primitive's create() / posture() / verify-opts validator runs validateOpts(opts, ALLOWED_KEYS, label) + validateOpts.requireObject + validateOpts.requireNonEmptyString + validateOpts.optionalY then assembles its domain-specific config (DaemonError pidfile / SelfUpdateError tag-and-asset / etc.). Thirteen different domains, thirteen different error classes; consolidating the prelude past the call boundary would surface the wrong error code on operator typos.",
    },
    {
      // [fp:9ee3419bf3f8]
      mode:  "family-subset",
      files: [
        "lib/audit-daily-review.js:create",
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/fdx.js:consentReceipt",
        "lib/http-client.js:_validateDownloadOpts",
        "lib/middleware/dpop.js:create",
        "lib/outbox.js:create",
        "lib/static.js:_validateCreateOpts",
        "lib/vault/seal-pem-file.js:sealPemFile",
        "lib/watcher.js:_validateOpts",
      ],
      reason: "http-client.downloadStream + watcher extension of the factory-create() opts-resolution scaffolding cluster documented above. Each primitive runs applyDefaults(opts, DEFAULTS) + validateOpts.optionalY + validateOpts.optionalZ cascades. Nine different domains (daily review / sanctions fetcher / FDX consent / HTTP download streamer / DPoP / outbox / static / sealed-PEM / file watcher); each closure captures a different downstream binding (HttpClientError vs WatcherError vs OutboxError, etc.).",
    },
    {
      // [fp:c1c6fe5e9ee1] — both 50-tok-10 and 60-tok-5/3 subsets
      mode:  "family-subset",
      files: [
        "lib/ai-adverse-decision.js:wrap",
        "lib/auth/access-lock.js:create",
        "lib/breach-deadline.js:createReporter",
        "lib/compliance-eaa.js:create",
        "lib/cra-report.js:create",
        "lib/gdpr-ropa.js:create",
        "lib/incident-report.js:create",
        "lib/network-byte-quota.js:create",
        "lib/nis2-report.js:create",
        "lib/vault/seal-pem-file.js:sealPemFile",
      ],
      reason: "network-byte-quota extension of the reporter-factory family. Each compliance reporter / quota gate runs validateOpts.requireObject(opts, ...) + validateOpts.requireNonEmptyString(opts.regulator, ...) + audit emitter wiring + closure-capture of regulator-specific deadline / threshold / sanction enums (GDPR 72h / CRA 24h+72h / NIS2 24h+72h / EAA / FDA-21CFR11 / netquota daily). Ten different regulator domains, ten different error classes (BreachDeadlineError / CraError / GdprError / IncidentError / NetworkByteQuotaError / NisError / EaaError / VaultError / AccessLockError / AiAdverseDecisionError); consolidating the prelude would lose the per-regime audit code.",
    },
    {
      // [fp:607d83252330]
      mode:  "family-subset",
      files: [
        "lib/ai-adverse-decision.js:wrap",
        "lib/daemon.js:_validateStartOpts",
        "lib/fdx.js:consentReceipt",
        "lib/self-update.js:_validateVerifyOpts",
        "lib/static.js:_validateCreateOpts",
      ],
      reason: "daemon + self-update validation prelude that shares the validateOpts.requireObject + validateOpts.requireNonEmptyString + validateOpts.optionalNonEmptyStringArray cascade with the AI-adverse-decision wrap / FDX consent / static-serve validators. Five different domains, five different error classes (DaemonError pidfile / SelfUpdateError tag / FdxError / AiAdverseDecisionError / StaticError); consolidating would couple unrelated primitives.",
    },
    {
      // [fp:6a0fb79e7569] — both 50-tok-5 and 50-tok-4 subsets
      mode:  "family-subset",
      files: [
        "lib/api-key.js:_validateIssueOpts",
        "lib/http-client.js:_validateDownloadOpts",
        "lib/self-update.js:_validateVerifyOpts",
        "lib/tcpa-10dlc.js:recordConsent",
        "lib/watcher.js:_validateOpts",
      ],
      reason: "http-client.downloadStream + self-update + watcher validation prelude that shares the validateOpts.requireNonEmptyString + validateOpts.optionalNonEmptyString + validateOpts.optionalPositiveFinite cascade with api-key issue and TCPA consent-record. Five different domains; consolidating past the call boundary would surface the wrong error code (ApiKeyError / HttpClientError / SelfUpdateError / TcpaError / WatcherError) on operator typos.",
    },
    {
      // [fp:f2d2478213be]
      files: [
        "lib/mail-arc-sign.js:sign",
        "lib/middleware/require-methods.js:create",
        "lib/network-tls.js:buildOptions",
        "lib/ws-client.js:connect",
      ],
      reason: "validateOpts.requireNonEmptyString + array-membership-check prelude — mail-arc-sign signature header + require-methods method whitelist + network-tls SNI + ws-client connect URL each gate operator-supplied input via validateOpts.requireNonEmptyString then run a follow-up domain check (RFC 8617 ARC tag / RFC 7231 method enum / IDN host / RFC 6455 ws scheme). Four different domains, four different error classes.",
    },
    {
      // [fp:b69223a64fea]
      files: [
        "lib/http-client.js:_validateDownloadOpts",
        "lib/mail-arc-sign.js:sign",
        "lib/tcpa-10dlc.js:recordConsent",
        "lib/watcher.js:_validateOpts",
      ],
      reason: "http-client.downloadStream + watcher extension of the four-way validateOpts.requireNonEmptyString + domain-shape-check cluster — RFC 6376 DKIM tag-list + TCPA-10DLC consent record + HTTP download URL/dest + filesystem watcher path. Four different domains, four different error classes (HttpClientError / MailArcSignError / TcpaError / WatcherError).",
    },
    {
      // [fp:161bc32b677a / fp:ade2ccf74c65 / fp:3f55833e9212]
      mode:  "family-subset",
      files: [
        "lib/middleware/require-content-type.js:_normalizeAllowed",
        "lib/network-tls.js:_normalizeCaInput",
        "lib/router.js:_matchCompiled",
        "lib/sandbox.js:_validateAllowed",
        "lib/watcher.js:_compileIgnore",
      ],
      reason: "watcher.ignore + sandbox.allowed + router.match + tls-ca + content-type-allowed compile-string-or-array idiom. Each primitive accepts an operator-supplied allow/ignore list as string|RegExp|Array<string|RegExp>, normalises every entry through the same `Array.isArray(x) ? x : [x]; for (i...) { if (typeof === 'string') ...; else if (instanceof RegExp) ...; else throw }` skeleton. Five different domains (HTTP content-type whitelist / TLS CA bundle normalisation / router path matcher compiler / sandbox allowlist / watcher gitignore-style matcher); each domain's per-entry validation differs (RFC 6838 token / X.509 PEM / route pattern / glob / gitignore-glob), so the per-element body diverges and only the outer compile loop shingles.",
    },
    {
      // [fp:c8ad2e9c9a17]
      mode:  "family-subset",
      files: [
        "lib/cookies.js:parseSafe",
        "lib/middleware/headers.js:_detectIssues",
        "lib/request-helpers.js:extractBearer",
        "lib/router.js:_matchCompiled",
      ],
      reason: "cookies.parseSafe + headers._detectIssues + extractBearer + router._matchCompiled all walk a request-supplied string with the same charCodeAt-driven scan and per-character branch (RFC 6265 cookie-name vs RFC 7230 tchar vs RFC 6750 b64token vs route segment). Four different parsers, four different acceptance grammars; consolidating would force a shared character-class table and lose RFC-specific guards.",
    },
    {
      // [fp:9b9760a9a051]
      files: [
        "lib/compliance-sanctions-fetcher.js:create",
        "lib/dsr.js:create",
        "lib/outbox.js:create",
        "lib/self-update.js:_validatePollOpts",
      ],
      reason: "self-update.poll-opts extension of the four-way factory-prelude cluster (sanctions-fetcher / DSR / outbox / self-update) that shares applyDefaults + validateOpts cascade. Four different domains, four different error classes (ComplianceSanctionsFetcherError / DsrError / OutboxError / SelfUpdateError).",
    },
    {
      // [fp:09ad583326fb] v0.12.6 — OTLP protobuf encoder addition extended
      // the otlp-exporter.js create() prelude into the same factory-prelude
      // cluster dsr + span-http-server already shared. Three different
      // domains (GDPR Art. 17 data-subject request, HTTP server-span auto-
      // wiring, OTLP trace exporter) with three distinct error classes
      // (DsrError / SpanHttpError / OtlpExporterError); the shingle is the
      // validateOpts(opts, [...key-list...], "<primitive>.create") boilerplate.
      files: [
        "lib/dsr.js:create",
        "lib/middleware/span-http-server.js:create",
        "lib/observability-otlp-exporter.js:create",
      ],
      reason: "v0.12.6 — OTLP protobuf encoder addition pulled observability-otlp-exporter.js:create into the same validateOpts + applyDefaults prelude cluster dsr + span-http-server already shared. Three different domains (GDPR Art. 17 data-subject request workflow / HTTP server-span auto-wiring / OTLP trace exporter) with three distinct error classes (DsrError / SpanHttpError / OtlpExporterError); the shingle is the per-primitive validateOpts(opts, [...key-list...], '<primitive>.create') call.",
    },
    {
      // [fp:b73d9d193b7b]
      files: [
        "lib/audit-daily-review.js:create",
        "lib/http-client.js:_validateDownloadOpts",
        "lib/static.js:_validateCreateOpts",
      ],
      reason: "http-client.downloadStream extension of the audit-daily-review + static-serve validator family — each opens with validateOpts.requireObject(opts, ...) then runs validateOpts.requireNonEmptyString cascades on operator-supplied url / dest / mountPath. Three different domains; consolidating would surface the wrong error code (AuditDailyReviewError / HttpClientError / StaticError) on operator typos.",
    },
    {
      // [fp:9d04e7890893]
      files: [
        "lib/http-client.js:_validateDownloadOpts",
        "lib/tcpa-10dlc.js:recordConsent",
        "lib/watcher.js:_validateOpts",
      ],
      reason: "http-client.downloadStream + tcpa-10dlc consent-record + watcher opts validator three-way subset of the validateOpts.requireNonEmptyString prelude family. Three different domains, three different error classes.",
    },
    {
      // [fp:2d057b219b88]
      files: [
        "lib/daemon.js:_readPidFile",
        "lib/daemon.js:_validateStartOpts",
        "lib/self-update.js:poll",
        "lib/watcher.js:_compileIgnore",
      ],
      reason: "daemon._readPidFile + daemon._validateStartOpts + self-update.poll + watcher._compileIgnore share a fs.readFileSync wrapped in try/catch + length-bound + parse skeleton. Four different domains (PID-file read / start opts validate / GitHub Releases poll / gitignore matcher compile); each handles ENOENT differently and the operator-facing error codes differ. Consolidating would couple unrelated primitives.",
    },
    {
      // [fp:6d22f9521131]
      files: [
        "lib/ai-pref.js:parseHeader",
        "lib/auth/step-up.js:parseChallenge",
        "lib/network-tls.js:_parseSanString",
      ],
      reason: "Comma-separated typed-entry parser idiom — split on `,`, trim each entry, locate the type/value separator, dispatch on the type token. ai-pref decodes RFC 9309-style AI-Pref header values; step-up parses RFC 9470 step-up auth challenge directives; network-tls parses Node's textual SAN format (`DNS:foo.example.com, IP Address:198.51.100.1`). Three different vocabularies (train/infer/snippet/price-usd vs acr_values/max_age/scope vs DNS/IP Address); each domain's grammar refuses unknown types and routes downstream to a domain-specific consumer. Consolidating would force a generic key-equals-value parser that loses every domain's per-token validation.",
    },
    {
      // [fp:c5e65a19ea64]
      files: [
        "lib/auth/step-up.js:parseChallenge",
        "lib/cookies.js:parse",
        "lib/cookies.js:parseSafe",
        "lib/network-tls.js:_normalizeIpForCompare",
      ],
      reason: "Quote-stripping + indexOf(separator) + slice(0, idx).trim() / slice(idx+1).trim() pair-splitter scaffold. Cookies parse RFC 6265 name=value pairs with double-quote stripping; step-up parses challenge directives with the same shape; network-tls strips bracket-quoted IPv6 literals (`[::1]` -> `::1`) before family detection. Three unrelated domains, each producing a domain-specific output (cookie name->value map vs challenge param map vs `{family, text, bytes}` IP record); consolidating would couple cookie-grammar / RFC 9470 directive grammar / IPv6-literal canonicalization into a single primitive that none of them want.",
    },
    {
      mode: "family-subset",
      files: [
        "lib/atomic-file.js:_readSyncCore",
        "lib/backup/bundle.js:create",
        "lib/network-tls.js:_readPathFile",
        "lib/vault/seal-pem-file.js:_resealNow",
      ],
      reason: "TOCTOU-safe file read scaffold: openSync(path, 'r') → fstatSync(fd) → bounded readSync loop into Buffer.allocUnsafe(stat.size) → closeSync. Each call site is the canonical fix for a js/file-system-race CodeQL finding — the open-fd-then-fstat sequence closes the swap window that exists between a separate existsSync/statSync and a subsequent readFileSync. Each site enforces its own max-size policy and emits a domain-typed error (AtomicFileError/atomic-file/too-large, BackupBundleError/backup-bundle/not-a-file, TlsTrustError surface, SealPemFileError/seal-pem-file/toctou-detected with extra inode-equality check); consolidating into a single primitive would erase the per-domain error-class + cap-vocabulary while only saving the inner read-loop. Future consolidation candidate as `b.atomicFile.readFd(filepath, opts)` once the inode-equality variant in seal-pem-file is reconciled with the simpler variants in atomic-file/backup/network-tls.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/agent-snapshot.js:_runHandler",
        "lib/auth/bot-challenge.js:verify",
        "lib/dsr.js:submit",
        "lib/mail-crypto-smime.js:_verifySignerInfo",
        "lib/self-update.js:poll",
      ],
      reason: "v0.11.25 — try / await / catch + typed-error rethrow + drop-silent audit emission scaffold. Each primitive wraps a single outbound effect (agent.snapshot.run / Cloudflare-Turnstile siteverify HTTPS POST / DSR-rights store write / CMS S/MIME SignerInfo verification / self-update poll) in the same `try { await x } catch (e) { _safeAudit(..., 'failure', {...}); throw new XxxError(code, msg) }` shape. The bodies enforce entirely different specs (agent-saga compensation / RFC 6960 / RFC 7522 / RFC 5652 / b.selfUpdate). Consolidating would couple unrelated effect domains and erase the per-primitive typed-error vocabulary.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/bot-challenge.js:verify",
        "lib/backup/index.js:create",
        "lib/db.js:declareRequireDualControl",
      ],
      reason: "v0.11.25 — opts-shape validation prelude pattern: each primitive walks an operator-supplied opts blob and refuses non-string / out-of-range / missing-field shapes with a typed error per its spec. Bot-challenge verify normalises Turnstile/hCaptcha/reCAPTCHA opts (token shape, action, hostname); backup.create asserts manifest / encryption / retention opts; db.declareRequireDualControl asserts column/table/policy opts. Each emits a distinct typed-error class with namespaced codes (bot-challenge/*, b-backup/*, db/*); consolidating would couple unrelated spec namespaces.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/bot-challenge.js:_normaliseAllowlist",
        "lib/middleware/cors.js:create",
        "lib/network-dns.js:setServers",
      ],
      reason: "v0.11.25 — allowlist-array normalisation prelude: each primitive walks an operator-supplied string-array (allowedHostnames + allowedActions for the bot-challenge verifier / CORS origin allowlist / DNS resolver server list), refuses non-strings + empty entries + zero-length lists, and emits a primitive-specific typed error. Bot-challenge bodies test exact-match against the embedded widget claim; CORS bodies test Origin-header membership; network-dns bodies test IPv4/IPv6 literal parsing. The shared shape is the validation prelude — consolidating would couple unrelated wire-format vocabularies (Turnstile/hCaptcha embedded claims vs Fetch Origin grammar vs RFC 1035 nameserver IP literals).",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/agent-orchestrator.js:create",
        "lib/auth/bot-challenge.js:_parseCloudflareLike",
        "lib/ws-client.js:connect",
      ],
      reason: "v0.11.25 — defensive object-shape read pattern: each primitive accepts a raw object (siteverify JSON response / agent-orchestrator opts / WebSocket close-frame payload) and normalises it into a typed internal shape via per-field `typeof === 'string' ? raw.X : null` guards. Bot-challenge bodies normalise Cloudflare/hCaptcha success+hostname+action+challenge_ts+error-codes; agent-orchestrator bodies normalise opts.topology+opts.leader+opts.health; ws-client bodies normalise the close-frame {code, reason}. The shared shape is the per-field typeof-then-null defensive read; the bodies enforce entirely different spec contracts (Cloudflare siteverify JSON vs b.agent.orchestrator topology vs RFC 6455 close-frame).",
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
    // The allowlist below is the survey ground truth from
    // memory/specs/node-26-map-getorinsert-migration.md. Adding a new
    // file here pre-floor-bump requires updating that spec in the same
    // patch so the sweep stays mechanical.
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
    primitive: "Map.prototype.getOrInsertComputed(key, factory) (Node 26+); pre-floor-bump call sites are allowlisted with a documented migration target in memory/specs/node-26-map-getorinsert-migration.md",
    // Variant A only — `var X = M.get(k); if (!X) { ... M.set(k, ...) ... }`.
    // Variant B (`if (!M.has(k)) { ... M.set(k, ...) ... }`) is caught
    // by the sibling `map-has-then-set-pre-node-26` entry below; one
    // regex per shape keeps V8's backtracking engine happy on large
    // files (an alternation `(?:A)|(?:B)` with backrefs + `[\s\S]{0,N}?`
    // triggered an OOM on the first attempt).
    regex: /var\s+\w+\s*=\s*\w+\.get\s*\([^;]+\)\s*;\s*\n\s*if\s*\(\s*!\s*\w+\s*\)\s*\{[\s\S]{0,300}?\.set\s*\(/,
    allowlist: [
      "lib/cache.js",                          // tagIndex (Map<tag, Set<key>>) — Set factory
      "lib/deprecate.js",                      // _seen (Map<name:since, entry>) — object-literal factory
      "lib/i18n-messageformat.js",             // _pluralRulesCache (Map<key, Intl.PluralRules>) — Intl factory
      "lib/i18n.js",                           // formatter cache (Map<key, formatter>) — closure factory
      "lib/mail-server-rate-limit.js",         // connectionTimes / authFailureTimes / rcptFailureTimes (3 sites) — array factory
      "lib/metrics.js",                        // counter / gauge `_ensure` / histogram observe (3 sites) — object-literal factory w/ cardinality cap
      "lib/middleware/rate-limit.js",          // token buckets (Map<key, bucket>) — object-literal factory
      "lib/network-byte-quota.js",             // store (Map<key, entry>) — `_newEntry()` factory
      "lib/observability-otlp-exporter.js",    // byResource grouping (Map<resKey, bucket>) — object-literal factory
      "lib/otel-export.js",                    // counters / observations (2 sites) — object-literal factory
      "lib/pubsub.js",                         // exactSubs (Map<channel, Set<sub>>) — Set factory
      "lib/backup/index.js",                   // bundleAdapterStorage.listBundles: byBundle (Map<bundleId, stats>) — object-literal factory
    ],
    // Strong-dup allowlists added with v0.12.7 archive substrate
    // — see KNOWN_CLUSTERS additions below for structural reasons.
    reason: "Node 26 ships Map.prototype.getOrInsertComputed(key, factory) — a single-lookup get-or-insert that replaces the two-step `var v = m.get(k); if (!v) { v = factory(); m.set(k, v); }` pattern. The sweep is deferred to the Node 26 floor-bump (eligible Oct 2026); engines.node is `>=24` today. Allowlist above is the survey ground truth from memory/specs/node-26-map-getorinsert-migration.md. New code post-this-patch trips the detector — either wait for the floor bump, or add the call site to BOTH the allowlist AND the migration spec in the same patch. When the floor moves, the bump commit walks the allowlist, rewrites each call site, drops the allowlist + flips the detector to enforce.",
  },
  {
    // Companion to `map-get-or-insert-pre-node-26` — same Node-26
    // migration target, different syntactic variant. Catches the
    // `if (!M.has(k)) { ... M.set(k, factory); ... }` shape (no
    // intermediate `var X = M.get(k)` binding). See the sibling entry
    // and memory/specs/node-26-map-getorinsert-migration.md.
    id: "map-has-then-set-pre-node-26",
    primitive: "Map.prototype.getOrInsertComputed(key, factory) (Node 26+); pre-floor-bump call sites are allowlisted with a documented migration target in memory/specs/node-26-map-getorinsert-migration.md",
    regex: /if\s*\(\s*!\s*\w+\.has\s*\([^)]+\)\s*\)\s*\{[\s\S]{0,300}?\.set\s*\(/,
    allowlist: [
      "lib/websocket-channels.js",             // channelToConns (Map<channel, Set<conn>>) — Set factory; cluster-shared race window
      // Edge cases — flagged structurally but do NOT migrate cleanly
      // to getOrInsertComputed:
      //
      //   - mail-greylist.js memoryStore.put runs `data.set(key, ...)`
      //     unconditionally (always overwrites the value); the if-block
      //     manages an evict-oldest sidecar `insertionOrder`. The
      //     migration spec marks it "manual review — does NOT replace
      //     cleanly" (sidecar logic stays).
      //   - dsr.js memoryTicketStore.update is a presence assertion:
      //     `if (!byId.has(id)) throw new DsrError(...)` followed by
      //     `byId.set(id, ...)` outside the if-block (it's an UPDATE,
      //     not an insert). The bounded `[\s\S]{0,300}?` crosses the
      //     closing `}` and matches the trailing `.set(`. False
      //     positive; migration is a no-op for this site.
      "lib/mail-greylist.js",
      "lib/dsr.js",
    ],
    reason: "Companion to map-get-or-insert-pre-node-26 — same Node 26 getOrInsertComputed migration target, captures the `if (!M.has(k)) { ... M.set(k, ...) ... }` syntactic variant. See sibling entry's reason and the migration spec.",
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
    regex: /\.slice\s*\(\s*1\s*\)\s*;[\s\S]{0,80}?if\s*\(\s*\w+\.length\s*>\s*0\s*\)\s*\{[\s\S]{0,160}?\bparseInt\s*\(/,
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
    regex: /switch\s*\(\s*\w*[Aa]lg\w*\s*\)\s*\{[\s\S]{0,1500}?default:\s*(?:return|break|\/\/[^\n]*\n\s*\})/,
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
    regex: /var\s+BIDI_RANGES\s*=\s*\[\s*0x200E[\s\S]{0,500}?function\s+_charClass/,
    allowlist: ["lib/codepoint-class.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg. The BIDI_RANGES + C0_CTRL_RANGES + ZERO_WIDTH_RANGES literal tables plus the _hex4 / _charClass / _fromCp helpers plus the `new RegExp(\"[\" + _charClass(...) + \"]\")` regex compilations were identical across 3 guard primitives by design. Centralized so the codepoint catalog has a single source of truth and future guards (filename / archive / mime / ...) consume the shared module instead of re-defining the tables.",
  },
  {
    id: "inline-resolve-profile-and-posture",
    primitive: "gateContract.resolveProfileAndPosture(opts, { profiles, compliancePostures, defaults, errorClass, errCodePrefix })",
    regex: /typeof\s+opts\.profile\s*===\s*["']string["'][\s\S]{0,300}?compliancePosture[\s\S]{0,300}?Object\.assign\(\{\}\s*,\s*[A-Z]+/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg. Every guard primitive's _resolveOpts opens with the identical `if (opts.profile) overlay = PROFILES[opts.profile]; if (opts.compliancePosture) overlay = Object.assign(overlay, COMPLIANCE_POSTURES[...]); return Object.assign({}, DEFAULTS, overlay, opts);` cascade. Centralized in gateContract so future guards consume the shared resolver — keeps the family resolution shape identical across members.",
  },
  {
    id: "inline-char-strip-policy-cascade",
    primitive: "codepointClass.applyCharStripPolicies(text, opts)",
    regex: /opts\.bidiPolicy\s*===\s*["']strip["'][\s\S]{0,200}?opts\.controlPolicy\s*===\s*["']strip["'][\s\S]{0,200}?opts\.nullBytePolicy/,
    allowlist: ["lib/codepoint-class.js"],
    reason: "Extracted across guard-html / guard-svg sanitize paths — the 4-line `if (opts.bidiPolicy === 'strip') s = s.replace(BIDI_RE_G, '')` cascade was identical. guard-csv uses different opt-name vocabulary (bidiCharPolicy / nullByteHandling) so it keeps its inline strip block; that's a single-vendor occurrence, below the duplicate-detector floor.",
  },
  {
    id: "inline-detect-char-threats",
    primitive: "codepointClass.detectCharThreats(text, opts, codePrefix)",
    regex: /var\s+bidiMatch\s*=\s*\w+\.match\(BIDI_RE\)[\s\S]{0,200}?bidi-override[\s\S]{0,300}?nullBytePolicy[\s\S]{0,200}?null-byte/,
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
    id: "inline-rule-pack-loader",
    primitive: "gateContract.makeRulePackLoader(errorClass, codePrefix)",
    regex: /var\s+_\w*[Rr]ulePacks?\s*=\s*\{\}[\s\S]{0,80}function\s+loadRulePack\s*\(\s*pack\s*\)\s*\{[\s\S]{0,200}?validateOpts\.requireObject[\s\S]{0,200}?validateOpts\.requireNonEmptyString[\s\S]{0,100}?_\w*[Rr]ulePacks?\[pack\.id\]\s*=\s*pack/,
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
    regex: /forensicEvidenceStore:\s*opts\.forensicEvidenceStore[\s\S]{0,400}?onAudit:\s*opts\.onAudit/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg gate(opts) factories. Every guard's gate() body forwarded the same ~16-key opts bag (mode / audit / observability / forensicEvidenceStore / cache / hooks / runtime cap / ...) to gateContract.defineGate; centralized so each guard's gate() body is just the check function plus a label.",
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
    regex: /typeof\s+input\s*===\s*["']string["'][\s\S]{0,80}?Buffer\.isBuffer\(input\)[\s\S]{0,200}?bad-input[\s\S]{0,300}?return\s*\{[\s\S]{0,80}?ok:\s*!issues\.some/,
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
    regex: /opts\.bidiPolicy\s*===\s*["']reject["'][\s\S]{0,150}?BIDI_RE\.test[\s\S]{0,200}?opts\.nullBytePolicy\s*===\s*["']reject["']/,
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
    regex: /opts\.observability\s*!==\s*undefined\s*&&\s*opts\.observability\s*!==\s*null[\s\S]{0,200}?event\s*!==\s*["']function["']/,
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
    id: "inline-optional-non-empty-string-array-validation",
    primitive: "validateOpts.optionalNonEmptyStringArray(value, label, ErrorClass, code?)",
    // Match the four-line cascade `if (opts.X !== undefined) { if
    // (!Array.isArray(opts.X)) throw ... ; for (i...) if (typeof opts.X[i]
    // !== "string" || opts.X[i].length === 0) throw }` — recurring across
    // api-key (scopes), file-upload (allowedFileTypes), seeders (dependsOn),
    // i18n (rtlLanguages / eagerLocales), and others.
    regex: /!\s*Array\.isArray\s*\(\s*\w+\.\w+\s*\)[\s\S]{0,400}?typeof\s+\w+\.\w+\s*\[\s*\w+\s*\]\s*!==\s*["']string["']\s*\|\|\s*\w+\.\w+\s*\[\s*\w+\s*\]\.length\s*===\s*0/,
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
    regex: /try\s*\{\s*onDrop\s*\(\s*\{[\s\S]{0,200}?\}\s*\)\s*;?\s*\}\s*catch/,
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
    regex: /"BEGIN"[\s\S]{0,400}?"COMMIT"[\s\S]{0,200}?\}\s*catch[\s\S]{0,300}?"ROLLBACK"/,
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
    regex: /!\s*\w+\.is\w*FiniteInt\s*\(\s*\w+\.\w+\s*\)[\s\S]{0,200}?\w+\.shape\s*\(\s*\w+\.\w+\s*\)/,
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
      "lib/object-store/gcs.js",
      "lib/object-store/sigv4.js",
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
    regex: /var\s+flushTimer\s*=\s*null\s*;[\s\S]{0,300}?if\s*\(\s*flushTimer/,
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
    regex: /try\s*\{[\s\S]{0,150}?observability\.event\s*\([^)]*\)\s*;?\s*\}\s*catch/,
    allowlist: [],
    reason: "Extracted to observability.safeEvent — drop-silent semantics for hot-path event emission. Any module wrapping observability.event in try/catch should call observability.safeEvent instead.",
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
    ],
    reason: "Identifier ALWAYS reaches SQL through safeSql.quoteIdentifier(name, dialect). Validates shape + quotes for the dialect; a future shape-regex bypass can't reach raw concatenation. Local variables holding quoted identifiers use a `q`/`Q`/`quoted` prefix so the detector can skip them.",
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
    ],
    reason: "Extracted to validateOpts.optionalPlainObject. Replaces the recurring `if (X !== undefined && X !== null) { if (typeof X !== 'object' || Array.isArray(X)) throw }` shape used to validate optional plain-object opts. Two sites allowlisted: external-db needs the permanent-flag 3rd arg the helper drops; protocol-dispatcher uses multi-line formatted error messages that don't fit the helper's description slot.",
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
    regex: /mountinfo[\s\S]{0,800}?options[\s\S]{0,80}?indexOf\(["']bind["']\)/,
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
    regex: /for\s*\(\s*var\s+\w+\s*=\s*0[^)]*\.(?:signerInfos|signers|recipients|items|entries)\.length[^)]*\)\s*\{[\s\S]{0,600}?\bverify\s*\(\s*\{/,
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
    regex: /\b(\w+)\s*=\s*\1\.then\([\s\S]{0,80}?set(?:Immediate|Timeout)\s*\(/,
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
    regex: /if\s*\(\s*(?:!\s*\w+\.get\s*\([^)]+\)|\w+\.get\s*\([^)]+\)\s*===\s*(?:undefined|null))\s*\)\s*\{[\s\S]{0,300}?\.set\s*\(/,
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
    regex: /\bfs\.(?:existsSync|statSync|lstatSync)\s*\(\s*(\w+)\s*\)[\s\S]{0,400}?\bfs\.(?:readFile|readFileSync|open|openSync|createReadStream|writeFile|writeFileSync)\s*\(\s*\1\b/,
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
    regex: /safeDecompress\s*\([\s\S]{0,300}?maxOutputBytes\s*:/,
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
    regex: /getDerivedHashSalt\s*\(\s*\)\s*\.toString\s*\(\s*["']hex["']\s*\)\s*\+|var\s+(\w+)\s*=\s*[\w.]*getDerivedHashSalt\s*\(\s*\)\s*;[\s\S]{0,200}?\b(\w+)\s*=\s*\1\s*\.toString\s*\(\s*["']hex["']\s*\)\s*;[\s\S]{0,200}?sha3Hash\s*\(\s*\2\s*\+/,
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
