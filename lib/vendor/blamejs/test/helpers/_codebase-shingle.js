// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * _codebase-shingle — shared shingle-scan helpers extracted from
 * test/layer-0-primitives/codebase-patterns.test.js so the heavy
 * tokenize + cross-file shingle scan can run inside worker_threads.
 *
 * The main `testNoDuplicateCodeBlocks` detector sharded across N
 * workers (N = os.cpus().length by default) each call into
 * `scanShard(absFiles, opts)` which returns a per-pass-per-size
 * fingerprint map. The main thread merges those maps and runs the
 * existing cluster-aggregation logic untouched.
 *
 * KEEP IN SYNC: the helpers below are the verbatim copies of the
 * functions previously inlined in codebase-patterns.test.js. Do not
 * fork the logic — change once here and the worker + the test stay
 * consistent.
 */

var fs   = require("fs");
var path = require("path");

// Same set as `_JS_KEYWORDS` in codebase-patterns.test.js.
var JS_KEYWORDS = new Set([
  "var", "let", "const", "function", "return", "if", "else", "for",
  "while", "do", "switch", "case", "default", "break", "continue",
  "try", "catch", "finally", "throw", "new", "this", "null", "undefined",
  "true", "false", "typeof", "instanceof", "in", "of", "delete", "void",
  "async", "await", "class", "extends", "super", "import", "export",
  "from", "as", "with", "yield", "static",
  "require", "module", "exports", "Buffer", "process", "console",
  "Promise", "Object", "Array", "String", "Number", "Boolean", "Date",
  "RegExp", "Error", "Math", "JSON", "Symbol", "Map", "Set", "WeakMap",
  "WeakSet", "Reflect", "Proxy",
]);

function normalizeJsLine(line) {
  line = line.replace(/\/\/.*$/, "");
  line = line.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, "_STR");
  line = line.replace(/(^|[=(,?:[;!&|]|\breturn\s|\bthrow\s|=>\s*)\/((?:\\.|[^/\\\n])+)\/[gimsuy]*/g,
                      "$1_RE");
  line = line.replace(/\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b|0x[0-9a-fA-F]+/g, "_NUM");
  line = line.replace(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g, function (name) {
    if (name === "_STR" || name === "_NUM" || name === "_RE") return name;
    return JS_KEYWORDS.has(name) ? name : "_ID";
  });
  line = line.replace(/([.(){}[\];,:?!&|^~<>=+\-*/%@])/g, " $1 ");
  line = line.replace(/\s+/g, " ").trim();
  return line;
}

function tokenizeFile(absPath, repoRoot) {
  var rel;
  try { rel = path.relative(repoRoot, absPath).replace(/\\/g, "/"); }
  catch (_e) { rel = absPath; }
  var content;
  try { content = fs.readFileSync(absPath, "utf8"); }
  catch (_e) { return null; }
  var lines = content.split(/\r?\n/);
  var tokens = [];
  for (var li = 0; li < lines.length; li++) {
    var rawLine = lines[li];
    if (/^\s*(\/\/|\*|\/\*)/.test(rawLine)) continue;
    var norm = normalizeJsLine(rawLine);
    if (norm.length === 0) continue;
    var lineToks = norm.split(/\s+/).filter(function (t) { return t.length > 0; });
    for (var ti = 0; ti < lineToks.length; ti++) {
      tokens.push({ tok: lineToks[ti], line: li + 1 });
    }
  }
  return { rel: rel, tokens: tokens };
}

function isBoilerplate(slice) {
  var toks = slice.map(function (t) { return t.tok; });
  var joined = toks.join(" ");
  var requireCallSeq = /\brequire\s+\(\s+_STR\s+\)/g;
  var requireCalls = (joined.match(requireCallSeq) || []).length;
  if (requireCalls >= 2) return true;
  if (requireCalls === 1 && slice.length <= 10) return true;
  if (/_ID\s+=\s+_ID\s+\(\s+function\s+\(\s+\)\s+\{\s+return\s+require\s+\(\s+_STR\s+\)/.test(joined)) return true;
  if (/_ID\s+\(\s+\)\s+\.\s+_ID\s+\(\s+_ID\s+,\s+_ID\s+,\s+_ID\s+\|\s+\|\s+\{\s+\}\s+\)/.test(joined)) return true;
  if (/!\s+_ID\s+\)\s+return\s+;\s+try\s+\{\s+_ID\s+\.\s+_ID\s+\(/.test(joined)) return true;
  var unpackSeq = /var\s+_ID\s+=\s+_ID\s+\.\s+_ID\s+;/g;
  var unpacks = (joined.match(unpackSeq) || []).length;
  if (unpacks >= 2) return true;
  var strCommaSeq = /_STR\s+,\s+_STR\s+,\s+_STR\s+,\s+_STR/g;
  if (strCommaSeq.test(joined)) return true;
  if (/_ID\s+\.\s+_ID\s+\.\s+_ID\s+\(\s+_NUM\s+\)\s+\/\s+_ID\s+\.\s+_ID\s+\.\s+_ID\s+\(\s+_NUM\s+\)/.test(joined)) return true;
  if (/_ID\s+\.\s+_ID\s+=\s+=\s+=\s+true\s+\|\s+\|\s+typeof\s+_ID\s+\.\s+_ID\s+=\s+=\s+=\s+_STR/.test(joined)) return true;
  if (/if\s+\(\s+_ID\s+\.\s+_ID\s+!\s+=\s+=\s+undefined\s+&\s+&\s+_ID\s+\.\s+_ID\s+!\s+=\s+=\s+null\s+\)/.test(joined)) return true;
  var validateChainSeq = /_ID\s+\.\s+_ID\s+\(\s+_ID\s+\.\s+_ID\s+,\s+_STR\s+,\s+_ID\s+\)\s+;/g;
  var validateChainCount = (joined.match(validateChainSeq) || []).length;
  if (validateChainCount >= 2) return true;
  if (/\bclass\s+_ID\s+extends\s+_ID/.test(joined)) return true;
  if (/\bclass\s+T\s+extends\s+T/.test(joined)) return true;
  if (/module\s+\.\s+exports\s+=\s+\{/.test(joined)) return true;
  var kvPairs = (joined.match(/_ID\s+:\s+_ID\s+,/g) || []).length;
  if (kvPairs >= 4) return true;
  if (/\bdefineClass\s+\(\s+_STR/.test(joined)) return true;
  var constantDeclSeq = /var\s+_ID\s+=\s+_ID\s+\.\s+_ID\s+\.\s+_ID\s+\(\s+_NUM\s+\)\s+;/g;
  var constantDecls = (joined.match(constantDeclSeq) || []).length;
  if (constantDecls >= 2) return true;
  var constantDeclSeq2 = /var\s+_ID\s+=\s+_ID\s+\.\s+_ID\s+\(\s+(?:_NUM|_STR)\s*[),]/g;
  var constantDecls2 = (joined.match(constantDeclSeq2) || []).length;
  if (constantDecls2 >= 3) return true;
  var declTokens = toks.filter(function (t) {
    return t === "=" || t === ";" || t === "," || t === ":" ||
           t === "_STR" || t === "_NUM" || t === "var" || t === "const";
  }).length;
  if (declTokens >= Math.floor(slice.length * 0.55)) return true;
  var rangeCheckSeq = /_ID\s+>\s+=\s+_NUM\s+&\s+&\s+_ID\s+<\s+=\s+_NUM/g;
  var rangeChecks = (joined.match(rangeCheckSeq) || []).length;
  if (rangeChecks >= 2) return true;
  if (/for\s+\(\s+var\s+_ID\s+=\s+_NUM\s+;\s+_ID\s+<\s+_ID\s+\.\s+_ID\s+;\s+_ID\s+\+\s+\+\s+\)/.test(joined)) return true;
  var throwTypeofSeq = /if\s+\(\s+typeof\s+_ID[\s\S]{0,40}?\)\s+\{\s+throw\s+new\s+_ID\s+\(\s+_STR\s+,\s+_STR\s+\)\s+;\s+\}/g;
  var throwTypeofs = (joined.match(throwTypeofSeq) || []).length;
  if (throwTypeofs >= 2) return true;
  return false;
}

// Same fingerprints as the inline versions. (Hash-based variant
// tested in v0.8.26 surfaced previously-grouped duplicates as
// distinct clusters — the join-on-space form preserves the cluster
// identity the existing KNOWN_CLUSTERS allowlist depends on.)
function sliceFingerprintExact(slice) {
  return slice.map(function (t) { return t.tok; }).join(" ");
}
function sliceFingerprintSkeleton(slice) {
  return slice.map(function (t) {
    var k = t.tok;
    if (/^[A-Za-z_]/.test(k)) return "T";
    return k;
  }).join(" ");
}

/**
 * scanShard(absFiles, opts) — tokenize the assigned files and run the
 * shingle scan. Returns:
 *   {
 *     exact:    { "<size>": { fp -> [{file, line, endLine}] } },
 *     skeleton: { "<size>": { fp -> [{file, line, endLine}] } }
 *   }
 *
 * The main thread merges per-(pass,size,fp) lists from every shard
 * and runs the existing cluster-aggregation logic.
 */
function scanShard(absFiles, opts) {
  opts = opts || {};
  var repoRoot = opts.repoRoot;
  var shingleSizes = opts.shingleSizes || [60, 50, 40, 30, 22, 16, 12, 8];
  var minDistinctTokens = opts.minDistinctTokens || 5;

  var out = { exact: {}, skeleton: {} };
  for (var sz = 0; sz < shingleSizes.length; sz += 1) {
    out.exact[shingleSizes[sz]] = {};
    out.skeleton[shingleSizes[sz]] = {};
  }

  var passes = [
    { label: "exact",    fpFn: sliceFingerprintExact,    bucket: out.exact    },
    { label: "skeleton", fpFn: sliceFingerprintSkeleton, bucket: out.skeleton },
  ];

  for (var fi = 0; fi < absFiles.length; fi += 1) {
    var entry = tokenizeFile(absFiles[fi], repoRoot);
    if (!entry) continue;
    var tokens = entry.tokens;
    var rel    = entry.rel;
    for (var si = 0; si < shingleSizes.length; si += 1) {
      var n = shingleSizes[si];
      if (tokens.length < n) continue;
      for (var ti = 0; ti + n <= tokens.length; ti += 1) {
        var slice = tokens.slice(ti, ti + n);
        var distinctMap = {};
        for (var di = 0; di < slice.length; di += 1) distinctMap[slice[di].tok] = true;
        if (Object.keys(distinctMap).length < minDistinctTokens) continue;
        if (isBoilerplate(slice)) continue;
        for (var pi = 0; pi < passes.length; pi += 1) {
          var pass = passes[pi];
          var fp = pass.fpFn(slice);
          var bucketForSize = pass.bucket[n];
          if (!bucketForSize[fp]) bucketForSize[fp] = [];
          bucketForSize[fp].push({
            file:    rel,
            line:    slice[0].line,
            endLine: slice[slice.length - 1].line,
          });
        }
      }
    }
  }
  return out;
}

module.exports = {
  JS_KEYWORDS:              JS_KEYWORDS,
  normalizeJsLine:          normalizeJsLine,
  tokenizeFile:             tokenizeFile,
  isBoilerplate:            isBoilerplate,
  sliceFingerprintExact:    sliceFingerprintExact,
  sliceFingerprintSkeleton: sliceFingerprintSkeleton,
  scanShard:                scanShard,
};
