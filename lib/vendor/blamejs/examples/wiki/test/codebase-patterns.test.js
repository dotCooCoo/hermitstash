"use strict";
/**
 * codebase-patterns (wiki edition) — automated grep gates for bug
 * classes that have surfaced in the framework's release history,
 * applied to the wiki app's own JavaScript surface.
 *
 * Mirror of test/layer-0-primitives/codebase-patterns.test.js in the
 * framework repo. Wiki-app code consumes `b = require("@blamejs/core")`,
 * so the canonical helpers are `b.constants.TIME.*` / `b.constants.BYTES.*`
 * (a.k.a. `C.TIME.*` / `C.BYTES.*` when imported as a binding). Same
 * pattern set, same fundamental-fix expectations — operator-shipped
 * apps shouldn't drift on the same bug classes the framework guards
 * against in its own internals.
 *
 * Scope:
 *   examples/wiki/lib/**.js
 *   examples/wiki/routes/**.js
 *   examples/wiki/seeders/**.js     (excluding seeders/prod/pages/* —
 *     those are HTML page fixtures whose embedded JS examples are
 *     already validated by validate-primitive-sections.js)
 *   examples/wiki/migrations/**.js
 *   examples/wiki/server.js
 *   examples/wiki/src/**.js         (if present)
 *
 * Allow markers (file-level + per-line) match the framework test's
 * convention so a wiki author needing a documented exception uses the
 * same shape:
 *
 *   1. File-level header within the first 50 lines:
 *        // codebase-patterns:allow-file <class> — <reason>
 *
 *   2. Per-line marker on the same line or one above:
 *        ... // allow:<class> — <reason>
 *
 * Run standalone:
 *   node examples/wiki/test/codebase-patterns.test.js
 *
 * Runs as part of wiki e2e:
 *   node examples/wiki/test/e2e.js
 */
var fs = require("fs");
var path = require("path");

var WIKI_ROOT = path.resolve(__dirname, "..");

var SCAN_DIRS = [
  path.join(WIKI_ROOT, "lib"),
  path.join(WIKI_ROOT, "routes"),
  path.join(WIKI_ROOT, "migrations"),
  path.join(WIKI_ROOT, "seeders"),
  path.join(WIKI_ROOT, "src"),
];

var SCAN_FILES = [
  path.join(WIKI_ROOT, "server.js"),
];

function _isSkippedPath(absPath) {
  var rel = path.relative(WIKI_ROOT, absPath).replace(/\\/g, "/");
  if (rel.indexOf("seeders/prod/pages/") === 0) return true;
  if (rel.indexOf("node_modules/") !== -1) return true;
  if (rel.indexOf("public/dist/") === 0) return true;
  if (rel.indexOf("public/vendor/") === 0) return true;
  if (rel.indexOf("data/") === 0 || rel.indexOf("data-e2e/") === 0) return true;
  return false;
}

function _walk(dir, files) {
  files = files || [];
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return files; }
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var full = path.join(dir, e.name);
    if (_isSkippedPath(full)) continue;
    if (e.isDirectory()) _walk(full, files);
    else if (e.isFile() && e.name.endsWith(".js")) files.push(full);
  }
  return files;
}

function _wikiFiles() {
  var out = [];
  for (var i = 0; i < SCAN_DIRS.length; i++) _walk(SCAN_DIRS[i], out);
  for (var j = 0; j < SCAN_FILES.length; j++) {
    if (fs.existsSync(SCAN_FILES[j])) out.push(SCAN_FILES[j]);
  }
  return out;
}

function _relPath(absPath) {
  return path.relative(WIKI_ROOT, absPath).replace(/\\/g, "/");
}

function _scan(regex, opts) {
  opts = opts || { skipComments: true };
  var matches = [];
  var files = _wikiFiles();
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

function _filterMarkers(matches, allowClass) {
  var fileCache = {};
  var fileAllowCache = {};
  function _readContext(file) {
    if (!fileCache[file]) {
      try {
        var p = path.resolve(WIKI_ROOT, file);
        fileCache[file] = fs.readFileSync(p, "utf8").split(/\r?\n/);
      } catch (_e) { fileCache[file] = []; }
    }
    return fileCache[file];
  }
  function _hasFileAllow(file) {
    if (Object.prototype.hasOwnProperty.call(fileAllowCache, file)) return fileAllowCache[file];
    var lines = _readContext(file).slice(0, 50);
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
var _allAdvisory = [];
var _checks = 0;

function _passing(label) {
  _checks++;
  console.log("  OK   " + label);
}

function _report(label, matches) {
  if (matches.length === 0) { _passing(label); return; }
  var preview = matches.map(function (m) {
    return "    " + m.file + ":" + m.line + ": " + m.content.slice(0, 100);
  }).join("\n");
  console.log("  FAIL " + label + ": " + matches.length + " violation(s):\n" + preview);
  _allViolations.push({ label: label, count: matches.length });
}

function _reportAdvisory(label, matches) {
  if (matches.length === 0) { _passing(label); return; }
  var preview = matches.map(function (m) {
    return "    " + m.file + ":" + m.line + ": " + m.content.slice(0, 100);
  }).join("\n");
  console.log("  ADVISORY " + label + ": " + matches.length + " candidate(s):\n" + preview);
  _allAdvisory.push({ label: label, count: matches.length });
}

function testNoRawByteLiterals() {
  var files = _wikiFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
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
      if (/\b(?:C|b\.constants)\.(BYTES|TIME)\.\w+\(/.test(stripped)) continue;
      var statusCmpRe = /[<>!=]=?\s*(?:200|300|400|500|600|399|599)\b|\b(?:200|300|400|500|600|399|599)\s*[<>!=]=?/;
      if (statusCmpRe.test(stripped)) continue;
      // Skip HTTP-status assignment / propagation contexts: any line
      // where a multiple-of-8 value sits in a status-code position
      // (`res.statusCode = N`, `_send(res, N, ...)`, `{ status: N }`,
      // `htmlString(res, ..., { status: N })`, `slice(0, N)` for
      // simple text-truncation bounds where N is in 100..999 range).
      // These domain values are RFC 7231 codes, not byte sizes.
      var statusAssignRe = /\b(status|statusCode|status_code|http_status)\s*[:=]/i;
      if (statusAssignRe.test(stripped)) continue;
      // The wiki's _send / htmlString helpers carry the status code
      // as the second positional argument.
      var statusArgRe = /\b(?:_send|htmlString|status|setStatus|writeHead)\s*\([^,]+,\s*(?:200|201|204|301|302|303|400|401|403|404|409|410|413|415|422|429|500|502|503|504)\b/;
      if (statusArgRe.test(stripped)) continue;
      stripped = stripped.replace(/(?:>>>?|<<)\s*\d+/g, "");
      stripped = stripped.replace(/[&|^]\s*\d+/g, "");
      var hit = false;
      var re = /\b(\d{1,})\b/g;
      var m;
      while ((m = re.exec(stripped)) !== null) {
        var n = Number(m[1]);
        if (!Number.isFinite(n)) continue;
        if (n < 8) continue;
        if (n % 8 !== 0) continue;
        if (n >= 1900 && n <= 2100) continue;
        hit = true;
        break;
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
  bad = _filterMarkers(bad, "raw-byte-literal");
  _report("no raw byte-shaped literals (n >= 8 && n % 8 === 0; use " +
          "b.constants.BYTES.* or name as protocol constant)", bad);
}

function testNoRawTimeLiterals() {
  var files = _wikiFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
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
      var hit = false;
      if (/[)\w]\s*\*\s*1000\b(?!\s*\*\s*1000)/.test(stripped)) hit = true;
      if (!hit) {
        if (/\b(?:C|b\.constants)\.TIME\.\w+\(/.test(stripped)) continue;
        var statusCmpRe = /[<>!=]=?\s*(?:200|300|400|500|600|399|599)\b|\b(?:200|300|400|500|600|399|599)\s*[<>!=]=?/;
        if (statusCmpRe.test(stripped)) continue;
        var re = /\b(\d{2,})\b/g;
        var m;
        while ((m = re.exec(stripped)) !== null) {
          var n = Number(m[1]);
          if (!Number.isFinite(n)) continue;
          if (n < 60) continue;
          if (n % 60 !== 0) continue;
          if (n >= 1900 && n <= 2100) continue;
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
  _report("no raw time-shaped literals (n >= 60 && n % 60 === 0; use " +
          "b.constants.TIME.* helpers)", bad);
}

function testNoStrayConsoleCalls() {
  var matches = _scan(/\bconsole\.(log|error|warn|info|debug)\(/);
  matches = _filterMarkers(matches, "console-direct");
  _report("no stray console.* calls (route through b.log)", matches);
}

function testNoUnresolvedMarkers() {
  var matches = _scan(/\b(TODO|FIXME|HACK|XXX)(?::|\s)/);
  matches = _filterMarkers(matches, "unresolved-marker");
  _report("no TODO / FIXME / HACK / XXX markers", matches);
}

function testNoTierTerminologyInCode() {
  var matches = _scan(/\bTier[- ]?(A|B|C)\b/i, { skipComments: false });
  matches = _filterMarkers(matches, "tier-terminology");
  _report("no Tier-A / Tier-B / Tier-C terminology", matches);
}

function testNoInlineRequires() {
  var matches = _scan(/^\s+\S.*\brequire\(["']\.\.?\//);
  matches = _filterMarkers(matches, "inline-require");
  _report("require() at top of file (or has inline-require allow marker)",
    matches);
}

function testNoMathRandomForSecurity() {
  var matches = _scan(/\bMath\.random\(/);
  matches = _filterMarkers(matches, "math-random-noncrypto");
  _report("Math.random() has explicit non-crypto allow marker", matches);
}

function testRawNewURL() {
  var matches = _scan(/\bnew URL\(/);
  matches = _filterMarkers(matches, "raw-new-url");
  _report("new URL(...) routes through b.safeUrl.parse", matches);
}

function testNoBareJsonParse() {
  var matches = _scan(/\bJSON\.parse\(/);
  matches = _filterMarkers(matches, "bare-json-parse");
  _report("JSON.parse on operator input routes through b.safeJson.parse",
    matches);
}

function testNoBareCanonicalizeWalks() {
  var matches = _scan(/Object\.keys\(\w+\)\.sort\(\)/);
  matches = _filterMarkers(matches, "bare-canonicalize-walk");
  _report("Object.keys(...).sort() canonicalize walks route through " +
          "b.canonicalJson", matches);
}

function testFormatValidatorLengthCap() {
  var files = _wikiFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (!/\b[A-Z_]+_RE\.test\(/.test(line)) continue;
      var window = (lines[li-2] || "") + (lines[li-1] || "") +
                   line + (lines[li+1] || "") + (lines[li+2] || "");
      if (/\.length\s*[><=]/.test(window)) continue;
      bad.push({
        file:    _relPath(files[fi]),
        line:    li + 1,
        content: line.trim(),
      });
    }
  }
  bad = _filterMarkers(bad, "regex-no-length-cap");
  _report("regex-only validators bound length before .test()", bad);
}

function testNoProcessExit() {
  var matches = _scan(/\bprocess\.exit\(/);
  matches = _filterMarkers(matches, "process-exit");
  _report("no process.exit() (server.js entry needs an allow marker)",
    matches);
}

function testNoSilentCatchSwallow() {
  var matches = _scan(/catch\s*\(\s*_\w*\s*\)\s*\{\s*\}/);
  matches = _filterMarkers(matches, "silent-catch");
  _report("empty catch(_e) {} blocks have explicit silent-catch allow marker",
    matches);
}

function testNoDynamicRegexFromOperatorInput() {
  var matches = _scan(/new RegExp\(/);
  matches = _filterMarkers(matches, "dynamic-regex");
  _report("new RegExp(...) marked with dynamic-regex allow marker " +
          "(input source documented)", matches);
}

function testNoRawXffRead() {
  var matches = _scan(/req\.headers\s*\[\s*["']x-forwarded-for["']\s*\]/i);
  matches = _filterMarkers(matches, "raw-xff");
  _report("req.headers['x-forwarded-for'] routes through b.requestHelpers.clientIp",
    matches);
}

function testNoRawRemoteAddress() {
  var matches = _scan(/\breq\.socket\.remoteAddress\b/);
  matches = _filterMarkers(matches, "raw-remote-addr");
  _report("req.socket.remoteAddress routes through b.requestHelpers.clientIp",
    matches);
}

function testNoRawProcessEnv() {
  var matches = _scan(/\bprocess\.env\.\w+/);
  matches = _filterMarkers(matches, "raw-process-env");
  _report("process.env reads route through b.safeEnv.readVar (or have allow marker)",
    matches);
}

function testNoRawTimingSafeEqual() {
  var matches = _scan(/\b(nodeCrypto|crypto)\.timingSafeEqual\(/);
  matches = _filterMarkers(matches, "raw-timing-safe-equal");
  _report("crypto.timingSafeEqual routes through b.crypto.timingSafeEqual",
    matches);
}

function testParseIntRadix() {
  var files = _wikiFiles();
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

// ============================================================
// Primitive-extraction-candidate detectors (advisory — surface
// patterns that should have been factored into a shared primitive
// rather than reinvented in the wiki app).
// ============================================================

function testNoHandrolledDeepClone() {
  // class: handrolled-deep-clone
  var matches = _scan(/\bJSON\.parse\s*\(\s*JSON\.stringify\s*\(/);
  matches = _filterMarkers(matches, "handrolled-deep-clone");
  _reportAdvisory("JSON.parse(JSON.stringify(x)) deep-clone → use " +
    "b.canonicalJson or structuredClone", matches);
}

function testNoBareErrorThrows() {
  // class: bare-error-throw
  // Wiki routes that throw plain Error skip the framework's structured
  // error contract. Rare in operator code but worth catching.
  var matches = _scan(/\bthrow\s+new\s+Error\s*\(/);
  matches = _filterMarkers(matches, "bare-error-throw");
  _reportAdvisory("throw new Error(string) → consider a typed error " +
    "(b.framework-error.defineClass) when callers dispatch on .code",
    matches);
}

function testNoHandrolledUrlBuild() {
  // class: handrolled-url-build
  var matches = _scan(/(["'])\s*\+\s*\w*[Ee]ndpoint\b|\b\w*[Ee]ndpoint\s*\+\s*["']\//);
  matches = _filterMarkers(matches, "handrolled-url-build");
  _reportAdvisory("string-concat URL build → use b.safeUrl.parse",
    matches);
}

function testTimersUnref() {
  var files = _wikiFiles();
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
  _report("setInterval timers call .unref() (or have allow marker)", bad);
}

function testNoRawRandomBytesToken() {
  var matches = _scan(/\b(nodeCrypto|crypto)\.randomBytes\([^)]+\)\s*\.\s*toString\s*\(/);
  matches = _filterMarkers(matches, "raw-randombytes-token");
  _report("nodeCrypto.randomBytes(n).toString routes through b.crypto.generateToken",
    matches);
}

function testNoHandrolledSleep() {
  var matches = _scan(/new Promise\([^)]*\)\s*=>\s*setTimeout|new Promise\(function[^{]*\{\s*setTimeout/);
  matches = _filterMarkers(matches, "handrolled-sleep");
  _report("Promise+setTimeout routes through b.safeAsync.sleep", matches);
}

function testNoRawOutboundHttp() {
  var matches = _scan(/\b(http|https)\.(request|get)\s*\(|^[^/]*\bfetch\s*\(/);
  matches = _filterMarkers(matches, "raw-outbound-http");
  _report("http(s).request / fetch route through b.httpClient", matches);
}

function testNoNumberEnvCoercion() {
  var matches = _scan(/\bNumber\s*\(\s*process\.env\b/);
  matches = _filterMarkers(matches, "number-env-coerce");
  _report("Number(process.env.X) routes through b.config.coerce.number / b.safeEnv typed readers",
    matches);
}

function run() {
  console.log("[wiki/codebase-patterns] scanning...");
  testNoRawByteLiterals();
  testNoRawTimeLiterals();
  testNoStrayConsoleCalls();
  testNoUnresolvedMarkers();
  testNoTierTerminologyInCode();
  testNoInlineRequires();
  testNoMathRandomForSecurity();
  testRawNewURL();
  testNoBareJsonParse();
  testNoBareCanonicalizeWalks();
  testFormatValidatorLengthCap();
  testNoProcessExit();
  testNoSilentCatchSwallow();
  testNoDynamicRegexFromOperatorInput();
  testNoRawXffRead();
  testNoRawRemoteAddress();
  testNoRawProcessEnv();
  testNoRawTimingSafeEqual();
  testParseIntRadix();
  testTimersUnref();
  testNoRawRandomBytesToken();
  testNoHandrolledSleep();
  testNoRawOutboundHttp();
  testNoNumberEnvCoercion();
  // Primitive-extraction advisories.
  testNoHandrolledDeepClone();
  testNoBareErrorThrows();
  testNoHandrolledUrlBuild();

  if (_allAdvisory.length > 0) {
    var totalAdv = _allAdvisory.reduce(function (a, v) { return a + v.count; }, 0);
    console.log("\n  ADVISORY SUMMARY: " + totalAdv + " primitive-extraction " +
      "candidate(s) across " + _allAdvisory.length + " class(es). These don't " +
      "fail the gate.");
  }

  if (_allViolations.length > 0) {
    console.error("[wiki/codebase-patterns] FAIL — " +
      _allViolations.reduce(function (a, v) { return a + v.count; }, 0) +
      " violation(s) across " + _allViolations.length + " class(es).");
    return 1;
  }
  console.log("[wiki/codebase-patterns] OK — " + _checks + " classes clean.");
  return 0;
}

module.exports = { run: run };

if (require.main === module) {
  var code = run();
  process.exit(code);
}
