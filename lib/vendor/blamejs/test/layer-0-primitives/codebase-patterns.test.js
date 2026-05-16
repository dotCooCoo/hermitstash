"use strict";
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

var LIB_ROOT = path.resolve(__dirname, "..", "..", "lib");

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

function testNoRawByteLiterals() {
  // class: raw-byte-literal
  // Systemic detection: any integer literal `n >= 8 && n % 8 === 0` is
  // a byte-shape candidate (8-bit alignment is the universal byte unit).
  // Use C.BYTES.kib / mib / gib (n) so the framework's byte math has a
  // single source of truth.
  // Strings, regex literals, and hex constants are excluded. HTTP
  // status comparisons, year literals (which can also be multiples of
  // 8), and lines already routed through C.BYTES.* are skipped.
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
        // Skip commonly-decimal protocol constants where
        // multiple-of-8 is coincidence:
        //   - 256, 64, 32, 16 — bit-widths (which ARE byte-aligned;
        //     fundamental fix routes them through C.BYTES.bit-arithmetic
        //     or names them as protocol constants).
        // No skip — flag every multiple of 8 strictly. The fundamental
        // fix path is to use C.BYTES helpers or rename + comment as a
        // protocol constant where 8-multiple is coincidence.
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
  _report("no raw byte-shaped literals (n >= 8 && n % 8 === 0; use " +
          "C.BYTES.kib / mib / gib or name as protocol constant)",
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

// ---- Release-named test files refused ----
// Tests must live in per-domain files (e.g. honeytoken.test.js,
// resource-access-lock.test.js) not release-bucket files like
// `v0-8-41-additions.test.js` or `slot-19-enhancements.test.js`.
// Buckets accumulate cross-domain assertions, drift in scope, and
// hide which primitive a test actually exercises. The discipline:
// one primitive → one test file; share helpers under test/helpers/.
function testNoReleaseNamedTestFiles() {
  var fs   = require("node:fs");
  var path = require("node:path");
  var hits = [];
  var releaseRe = /^v\d+[-_.]\d+[-_.]\d+([-_.]|$)/i;
  var slotRe    = /^slot[-_]\d+/i;
  var batchRe   = /(^|[-_])batch[-_.]/i;
  function walk(dir) {
    var entries = fs.readdirSync(dir, { withFileTypes: true });
    for (var i = 0; i < entries.length; i += 1) {
      var e = entries[i];
      if (e.name === "node_modules" || e.name === "helpers") continue;
      var full = path.join(dir, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (!e.isFile() || !/\.test\.js$/.test(e.name)) continue;
      if (releaseRe.test(e.name) || slotRe.test(e.name) || batchRe.test(e.name)) {
        hits.push({
          file: path.relative(path.resolve(__dirname, "..", ".."), full).replace(/\\/g, "/"),
          line: 1,
          content: "release-named / slot-named / batch-named test file (e.g. v0-8-41-... / v0_8_70-batch... / slot-19-...) — split into per-domain test files instead",
        });
      }
    }
  }
  walk(path.resolve(__dirname, "..", ".."));
  _report("no release-named / slot-named / batch-named test files (split into per-domain test files; one primitive → one test)",
    hits);
}

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
  //   MIN_DISTINCT_FILES — threshold for cross-file repetition. 3+
  //     means "appears in at least 3 files" (drift candidate).
  //   MIN_DISTINCT_TOKENS — skip shingles whose tokens are mostly
  //     punctuation / repeated closer chars.
  //   MAX_REPORTED_PER_LENGTH — cap to keep the report scannable;
  //     biggest-N hits are surfaced first because they represent the
  //     largest primitive opportunities.
  var SHINGLE_SIZES = [60, 50, 40, 30, 22, 16, 12, 8];
  var MIN_DISTINCT_FILES = 2;          // ≥ 3 files share the shape
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
        "lib/network-dns-resolver.js:<top>",
      ],
      reason: "Top-of-file JSDoc + module banner block — each module ships an @module / @nav / @title / @intro / @card scaffold per the wiki source-driven convention (rule §10). The shingle similarity is the banner shape, not behaviour. Removing or consolidating the banners would break the wiki auto-derivation.",
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
      reason: "Generic opt-validation entry — validateOpts.requireObject + a cascade of requireNonEmptyString / requireFiniteNumber / etc. calls. Every operator-facing primitive's create()/issue()/verify() entry opens this way per the tiered-validation discipline (CLAUDE.md rule §5). Tokens collide because validateOpts is the single source of truth for opt-validation shape; that's the point of having it. Each call site validates structurally different opt-shapes — consolidation would couple unrelated primitives.",
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
        "lib/mail-mdn.js:_validateOpts",
        "lib/mail-mdn.js:build",
        "lib/self-update.js:poll",
        "lib/watcher.js:_detectAutoMode",
      ],
      reason: "Generic JS lambda + object-assign + closure boilerplate. Any subset of these unrelated primitives (daemon PID-file read, data-act DSR third-party share / EU Data Act product declaration, dkim dualSigner merge / bootstrap keypair mint, MDN boundary / opt validation / report build, self-update release polling, watcher fs.watch mode detection) can cluster via the 50-token shingle. Distinct domains: process lifecycle / privacy compliance / mail crypto / mail DSN / framework self-update / fs watching. The shared shape is structural boilerplate, not behavior.",
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
        "lib/mail-server-pop3.js:create",
        "lib/mail-server-pop3.js:listen",
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
        "lib/guard-jmap.js:_resolveProfile",
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
        "lib/auth/dpop.js:_canonicalJwk",
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
        "lib/auth/dpop.js:_canonicalJwk",
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
        "lib/cdn-cache-control.js:_splitTopLevelCommas",
        "lib/client-hints.js:_splitTopLevelSemis",
        "lib/http-client-cache.js:_splitTopLevelCommas",
        "lib/http-message-signature.js:_splitTopLevelSemis",
      ],
      reason: "Quote-aware top-level structured-fields splitter — walks a string respecting RFC 8941 §3.3.3 quoted-string state with backslash-escape so `,` (cdn-cache-control / http-client-cache) or `;` (client-hints brand-member params / http-message-signature Signature-Input params) inside quoted-string values doesn't split mid-value. Same shape replicated across four parsers because they each split on a different delimiter for a different RFC; consolidation candidate via a shared `b.structuredFields.splitTopLevel(s, sep)` helper but the per-file copy is intentional pending the extraction (operator-grep finds the splitter inside the file that uses it).",
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
        "lib/auth/dpop.js:_canonicalJwk",
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
        "lib/auth/fido-mds3.js:_verifyJwsSignature",
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
        "lib/guard-smtp-command.js:_validateAuth",
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
        "lib/auth/dpop.js:_canonicalJwk",
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

function testNoStateStampsInPublicDocs() {
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
    ],
    reason: "Extracted to dbSchema.runInTransaction. Replaces the inline BEGIN / COMMIT / ROLLBACK try/catch boilerplate in migrations / seeders / db-schema. Handles both raw better-sqlite3 and b.db framework wrapper handles via runSqlOnHandle.",
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

function testKnownAntipatterns() {
  // class: known-antipattern
  // Fires at n=1 — any file matching a registered antipattern (and not
  // in its allowlist) fails the gate with a pointer to the primitive
  // that should replace it.
  var files = _libFiles();
  var allBad = [];
  for (var ai = 0; ai < KNOWN_ANTIPATTERNS.length; ai++) {
    var ap = KNOWN_ANTIPATTERNS[ai];
    var allowSet = Object.create(null);
    for (var k = 0; k < ap.allowlist.length; k++) allowSet[ap.allowlist[k]] = true;
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var rel = _relPath(files[fi]);
      if (allowSet[rel]) continue;
      var content;
      try { content = fs.readFileSync(files[fi], "utf8"); }
      catch (_e) { continue; }
      var m = ap.regex.exec(content);
      if (!m) continue;
      // Compute line number from match index.
      var lineNum = content.slice(0, m.index).split(/\r?\n/).length;
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

async function run() {
  testNoRawByteLiterals();
  testNoRawTimeLiterals();
  testNumericOptsValidate();
  testHttp2TeardownPaired();
  testNoStrayConsoleCalls();
  testNoUnresolvedMarkers();
  testNoLiteralNulBytesInSource();
  testNoReleaseNamedTestFiles();
  testParserPrimitivesHaveFuzzHarness();
  testNoTierTerminologyInLib();
  testNoInlineRequires();
  testRequireBindingConsistency();
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
  testNoStateStampsInPublicDocs();
  testNoLegacyUrlFormat();
  testNoDeniedVendors();
  // v0.8.91 bug-class detectors — derived from the
  // mail-require-tls / fal.meets / cdn-cache-control / SRS fix-ups.
  testTrimBeforeControlByteScan();
  testEnumRankWithoutValidation();
  testNoBoolStringCoerceShape();
  testNoBareCommaSplitOnQuotedHeader();
  testScopedContextBindingUsed();
  testGitleaksTrippingPatternsAllowlisted();
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
