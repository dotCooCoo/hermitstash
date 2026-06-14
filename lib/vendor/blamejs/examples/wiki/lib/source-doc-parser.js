"use strict";
// source-doc-parser — extract @primitive / @module wiki blocks from
// framework lib/*.js source files.
//
// Tag-ordering convention (enforced by validate-source-comment-blocks):
//
//   1. Single-line tags first: @primitive, @signature, @since,
//      @status, @compliance, @related, @anchor, @headingTag
//   2. Then the prose body (untagged lines — paragraphs separated
//      by blank lines).
//   3. Multi-line tags LAST: @opts, @example, @exampleFile, @intro.
//      These accumulate every following line as their value until the
//      next @-tag or block end — so any prose that sneaks in after
//      them gets silently swallowed into the previous multi-line tag.
//
// Schema (lives in JSDoc-style /** */ comment blocks immediately
// preceding the function or at the top of the module):
//
//   /**
//    * @primitive   b.csv.parse
//    * @signature   b.csv.parse(input, opts?)
//    * @since       0.4.0
//    * @status      stable
//    * @compliance  gdpr, soc2
//    * @related     b.csv.stringify, b.guardCsv
//    *
//    * Description prose. Multiple paragraphs separated by blank
//    * lines. Inline `code` and links pass through.
//    *
//    * @example
//    *   var rows = b.csv.parse("name,age");
//    *
//    * @exampleFile csv/parse.example.js   (alternative to @example)
//    */
//   function parse(input, opts) { ... }
//
// Module-level block (one per file, tagged @module):
//
//   /**
//    * @module b.uuid
//    *
//    * @intro
//    *   Namespace-wide prose.
//    */
//
// The parser is intentionally regex-based — no AST dependency. Three
// passes:
//   1. extractBlocks(source)   - array of raw block strings
//   2. parseBlock(rawBlock)    - { kind, tags, prose }
//   3. parseFile(source, path) - { module?, primitives: [...] }

var path = require("node:path");
var fs   = require("node:fs");

var BLOCK_RE = /\/\*\*([\s\S]*?)\*\//g;

var SINGLE_LINE_TAGS = {
  primitive:   true,
  module:      true,
  concept:     true,
  // @abiTemplate <factoryKind> — single-sourced ABI doc text for a
  // factory-generated guard method (defineGuard / defineParser). Routed
  // to a separate template bucket, NOT the primitive list, so it renders
  // per guard instead of as a gateContract primitive. @method names the
  // ABI method the template documents.
  abiTemplate: true,
  method:      true,
  title:       true,
  nav:         true,
  order:       true,
  slug:        true,
  featured:    true,
  signature:   true,
  since:       true,
  status:      true,
  compliance:  true,
  related:     true,
  exampleFile: true,
  anchor:      true,
  headingTag:  true,
};

var MULTI_LINE_TAGS = {
  intro:       true,
  example:     true,
  opts:        true,
  section:     true,
  card:        true,
};

// Strip the smallest common leading-whitespace prefix from a block of
// lines. Matches Python's textwrap.dedent. Authors who indent a
// multi-line @example by 2 spaces in the source comment shouldn't see
// that indentation leak into the rendered <pre> block.
function _dedent(text) {
  if (!text) return text;
  var lines = text.split("\n");
  // Find min indent across non-empty lines.
  var minIndent = Infinity;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line.trim()) continue;
    var m = line.match(/^[ \t]*/);
    var indent = m ? m[0].length : 0;
    if (indent < minIndent) minIndent = indent;
  }
  if (!isFinite(minIndent) || minIndent === 0) return text;
  return lines.map(function (l) {
    return l.length >= minIndent ? l.slice(minIndent) : l;
  }).join("\n");
}

function _stripCommentMarker(line) {
  // Strip trailing \r FIRST so the tag regex's `$` anchor matches at
  // end-of-line (the regex doesn't treat \r as a line terminator;
  // without this, every CRLF-line tag appears unmatchable).
  return line.replace(/\r$/, "").replace(/^\s*\*\s?/, "");
}

function _normalizeBlock(raw) {
  return String(raw).split("\n").map(_stripCommentMarker);
}

function parseBlock(raw) {
  var lines = _normalizeBlock(raw);
  var tags = {};
  var prose = [];
  var current = null;
  // Track ordering: did any prose appear AFTER a multi-line tag opened?
  // The validator surfaces this as "multi-line tag preceded prose"
  // because that prose got swallowed into the tag's value.
  var sawMultiLineThenProse = false;
  var openedMultiLine = false;

  function _flushMulti() {
    if (!current) return;
    var key = current.tag;
    var raw = current.lines.join("\n").replace(/^\n+|\n+$/g, "");
    // Strip per-line trailing whitespace too — comment-block authors
    // often leave a trailing space on the " * " marker line that
    // becomes a stray space at the end of the rendered code block.
    raw = raw.split("\n").map(function (l) {
      return l.replace(/\s+$/, "");
    }).join("\n").replace(/\n+$/, "");
    // Dedent multi-line tag bodies — author indentation (commonly 2-3
    // spaces inside the comment block) shouldn't leak into rendered
    // output. @example/@intro/@opts/@section all benefit; the dedent
    // is a no-op when authors didn't indent.
    var value = _dedent(raw);
    if (key === "example") {
      if (!Array.isArray(tags.examples)) tags.examples = [];
      tags.examples.push(value);
    } else if (key === "section") {
      // @section blocks accumulate as an ordered list. The first line
      // is the section heading; following lines are the body. Lets a
      // @concept block carry several sub-headings without a separate
      // tag per heading.
      if (!Array.isArray(tags.sections)) tags.sections = [];
      var lines = value.split("\n");
      var heading = lines.shift();
      tags.sections.push({
        heading: (heading || "").replace(/^\s+|\s+$/g, ""),
        body:    lines.join("\n").replace(/^\n+|\n+$/g, ""),
      });
    } else {
      tags[key] = value;
    }
    current = null;
  }

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var tagMatch = line.match(/^\s*@([a-zA-Z][a-zA-Z0-9]*)\b\s*(.*)$/);
    if (tagMatch) {
      _flushMulti();
      var tag = tagMatch[1];
      var rest = tagMatch[2];
      if (SINGLE_LINE_TAGS[tag]) {
        tags[tag] = rest.trim();
      } else if (MULTI_LINE_TAGS[tag]) {
        current = { tag: tag, lines: rest ? [rest] : [] };
        openedMultiLine = true;
      } else {
        tags[tag] = rest.trim();
      }
      continue;
    }
    if (current) {
      current.lines.push(line);
      // Heuristic: a non-blank line that looks like a sentence (starts
      // with a capital letter and ends with a period) inside a
      // multi-line tag's body is *probably* prose the author placed in
      // the wrong order. Mark it; the validator surfaces it.
      var trimmed = line.replace(/^\s+|\s+$/g, "");
      if (openedMultiLine && /^[A-Z]/.test(trimmed) && /[.!?]$/.test(trimmed)) {
        sawMultiLineThenProse = true;
      }
      continue;
    }
    prose.push(line);
  }
  _flushMulti();

  // Detect mixed-kind blocks — a single block declaring more than one
  // of @primitive / @module / @concept. The validator surfaces these
  // because the parser has to pick ONE kind silently and the unused
  // tag is hidden.
  var kindFlags = [];
  if (tags.primitive) kindFlags.push("primitive");
  if (tags.module) kindFlags.push("module");
  if (tags.concept) kindFlags.push("concept");
  // @abiTemplate blocks are a distinct kind — single-sourced ABI doc
  // text routed to the per-factory template bucket, never the primitive
  // list. They carry no @primitive tag, so they don't trip mixedKind.
  if (tags.abiTemplate) kindFlags.push("abiTemplate");
  var kind = kindFlags[0] || null;
  var mixedKind = kindFlags.length > 1 ? kindFlags : null;

  var proseText = prose.join("\n").replace(/^\n+|\n+$/g, "");

  return {
    kind:  kind,
    tags:  tags,
    prose: proseText,
    // Ordering signal — surfaced by validate-source-comment-blocks so
    // a wrong-order block fails the gate instead of silently producing
    // an empty prose body.
    proseAfterMultiLine: sawMultiLineThenProse,
    // Mixed-kind signal — the block declared more than one of
    // @primitive / @module / @concept. Surfaced as a finding because
    // the parser silently picks one and the others are hidden.
    mixedKind: mixedKind,
  };
}

function extractBlocks(source) {
  var blocks = [];
  BLOCK_RE.lastIndex = 0;
  var m;
  while ((m = BLOCK_RE.exec(source)) !== null) {
    blocks.push({
      raw:      m[1],
      startIdx: m.index,
    });
  }
  return blocks;
}

// Detect a guard-family factory call at module scope:
//   module.exports = [ns.]defineGuard({ ...
//   module.exports = [ns.]defineParser({ ...
// Returns { kind, errorClass } or null. The errorClass is read from the
// spec's `errorClass: Ident` (the guard supplies a pre-built class) and
// falls back to a `Guard<Name>Error` stem derived from `errorName:` or
// `name:` — matching the factory's own default-class minting — so the
// rendered ABI template's `{ERR}` placeholder resolves even when the
// guard lets the factory mint the class.
function _detectFactory(source) {
  var m = source.match(/module\.exports\s*=\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*\.)?define(Guard|Parser)\s*\(\s*\{/);
  if (!m) return null;
  var kind = "define" + m[1];
  // Scan the spec object literal (bracket-counted) for errorClass /
  // errorName / name / errCodePrefix.
  var openIdx = m.index + m[0].lastIndexOf("{");
  var spec = _sliceObjectLiteral(source, openIdx);
  var errorClass = null;
  var name = null;
  var errCodePrefix = null;
  if (spec) {
    var nameMatch = spec.match(/(^|[\s,{])name\s*:\s*["']([^"']+)["']/);
    if (nameMatch) name = nameMatch[2];
    var ecpMatch = spec.match(/(^|[\s,{])errCodePrefix\s*:\s*["']([^"']+)["']/);
    if (ecpMatch) errCodePrefix = ecpMatch[2];

    var ecMatch = spec.match(/(^|[\s,{])errorClass\s*:\s*([a-zA-Z_$][a-zA-Z0-9_$]*)/);
    if (ecMatch) {
      errorClass = ecMatch[2];
    } else {
      var enMatch = spec.match(/(^|[\s,{])errorName\s*:\s*["']([^"']+)["']/);
      if (enMatch) {
        errorClass = enMatch[2];
      } else if (name) {
        errorClass = _defaultErrorClassName(name);
      }
    }
  }
  // Error-code prefix mirrors the factory: errCodePrefix || name. This is
  // the stem used in thrown codes ("csv.bad-posture"), which differs from
  // the namespace ("guardCsv") — the ABI templates carry both placeholders.
  return {
    kind:          kind,
    errorClass:    errorClass,
    codePrefix:    errCodePrefix || name,
  };
}

// Mirror gate-contract.js's default-class stem: Guard + PascalCase(name) +
// Error (name's leading char upper-cased, rest verbatim — matches
// `"Guard" + name.charAt(0).toUpperCase() + name.slice(1) + "Error"`).
function _defaultErrorClassName(name) {
  if (!name) return null;
  return "Guard" + name.charAt(0).toUpperCase() + name.slice(1) + "Error";
}

// Return the substring of `source` spanning the object literal whose
// opening brace is at `openIdx` (inclusive of both braces), string- and
// comment-aware so braces inside strings / comments don't miscount.
function _sliceObjectLiteral(source, openIdx) {
  var i = openIdx + 1;
  var depth = 1;
  var inStr = null;
  var inSlash = false;
  var inBlock = false;
  var prev = "";
  while (i < source.length && depth > 0) {
    var c = source[i];
    if (inSlash) {
      if (c === "\n") inSlash = false;
    } else if (inBlock) {
      if (prev === "*" && c === "/") inBlock = false;
    } else if (inStr) {
      if (c === "\\") { i += 2; prev = source[i - 1]; continue; }
      if (c === inStr) inStr = null;
    } else if (c === "/" && source[i + 1] === "/") {
      inSlash = true;
    } else if (c === "/" && source[i + 1] === "*") {
      inBlock = true;
    } else if (c === '"' || c === "'" || c === "`") {
      inStr = c;
    } else if (c === "{") {
      depth++;
    } else if (c === "}") {
      depth--;
    }
    prev = c;
    i++;
  }
  if (depth !== 0) return null;
  return source.slice(openIdx, i);
}

function parseFile(source, sourcePath) {
  var blocks = extractBlocks(source);
  var module_ = null;
  var primitives = [];
  var concepts = [];
  var abiTemplates = [];
  for (var i = 0; i < blocks.length; i++) {
    var parsed = parseBlock(blocks[i].raw);
    if (!parsed.kind) continue;
    if (parsed.kind === "module") {
      if (module_) {

        console.warn("[source-doc-parser] duplicate @module block in", sourcePath); // allow:console-direct — wiki seeder helper, runs at boot before b.log is wired
      }
      module_ = parsed;
    } else if (parsed.kind === "primitive") {
      primitives.push(parsed);
    } else if (parsed.kind === "concept") {
      concepts.push(parsed);
    } else if (parsed.kind === "abiTemplate") {
      abiTemplates.push(parsed);
    }
  }
  return {
    sourcePath:   sourcePath,
    module:       module_,
    primitives:   primitives,
    concepts:     concepts,
    // ABI doc templates declared in this file (only gate-contract.js
    // carries them today). parseTree aggregates them across the tree.
    abiTemplates: abiTemplates,
    // Guard-family factory detection — populated when this file's
    // module.exports is a defineGuard / defineParser call. Drives the
    // page generator's per-guard ABI-method synthesis.
    factory:      _detectFactory(source),
  };
}

function parseTree(rootDir) {
  var byPath = {};
  function _walk(dir) {
    var entries;
    try { entries = fs.readdirSync(dir); } catch (_e) { return; }
    for (var i = 0; i < entries.length; i++) {
      var name = entries[i];
      // Skip vendored libs + node_modules; they're not framework source.
      if (name === "vendor" || name === "node_modules") continue;
      var full = path.join(dir, name);
      var stat;
      try { stat = fs.statSync(full); } catch (_e) { continue; }
      if (stat.isDirectory()) { _walk(full); continue; }
      if (!stat.isFile()) continue;
      if (!/\.js$/.test(name)) continue;
      // CodeQL js/file-system-race defense — fd-based read binds the
      // bytes we parse to the inode fs.statSync just measured. Even
      // though the wiki doc-parser walks framework source files (not
      // attacker-controlled), narrowing to a single fd matches the
      // discipline of the rest of the framework's read paths.
      var src;
      try {
        var srcFd = fs.openSync(full, "r");
        try {
          var srcStat = fs.fstatSync(srcFd);
          var srcBuf = Buffer.alloc(srcStat.size);
          var srcRead = 0;
          while (srcRead < srcStat.size) {
            var srcN = fs.readSync(srcFd, srcBuf, srcRead, srcStat.size - srcRead, null);
            if (srcN === 0) break;
            srcRead += srcN;
          }
          src = srcBuf.slice(0, srcRead).toString("utf8");
        } finally {
          try { fs.closeSync(srcFd); } catch (_c) { /* close best-effort */ }
        }
      } catch (_e) { continue; }
      var parsed = parseFile(src, full);
      if (parsed.module || parsed.primitives.length > 0 || parsed.concepts.length > 0) {
        byPath[full] = parsed;
      }
    }
  }
  _walk(rootDir);
  return byPath;
}

// Aggregate every @abiTemplate block across a parsed tree into a map
// keyed by factory kind ("defineGuard" / "defineParser"). Each value is
// an array of template records ({ kind:"abiTemplate", tags, prose }).
// Both the page generator (to synthesize per-guard ABI sections) and the
// comment-block validator (to register the templated method sigs as
// resolvable @related targets) read from this single derivation.
function factoryTemplates(byPath) {
  var byKind = { defineGuard: [], defineParser: [] };
  Object.keys(byPath).forEach(function (file) {
    var tpls = byPath[file].abiTemplates || [];
    tpls.forEach(function (t) {
      var kind = t.tags && t.tags.abiTemplate;
      if (!kind) return;
      if (!byKind[kind]) byKind[kind] = [];
      byKind[kind].push(t);
    });
  });
  return byKind;
}

module.exports = {
  parseBlock:       parseBlock,
  parseFile:        parseFile,
  parseTree:        parseTree,
  extractBlocks:    extractBlocks,
  factoryTemplates: factoryTemplates,
};
