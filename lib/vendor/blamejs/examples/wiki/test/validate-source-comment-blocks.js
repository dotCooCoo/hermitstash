"use strict";
// validate-source-comment-blocks — e2e gate for the source-driven
// wiki pipeline (lib/<file>.js -> wiki.config.js -> page-generator.js).
//
// Walks every namespace declared in wiki.config.js + every @module-
// tagged file under lib/ and asserts:
//
//   1. Every primitive @primitive block carries the required tags:
//      - @primitive   <b.X.Y>
//      - @signature   <b.X.Y(...)>
//      - prose body   (non-empty)
//      - example      (@example or @exampleFile)
//
//   2. @signature starts with `b.` and matches @primitive's namespace.
//
//   3. @status is one of: stable | experimental | deprecated.
//
//   4. @since looks like semver (X.Y.Z, optional pre-release).
//
//   5. @compliance values are drawn from the framework's posture
//      catalog. Unknown postures fail the gate.
//
//   6. @related references resolve to a primitive that either lives
//      in another @primitive block somewhere under lib/, OR appears
//      as a heading in a hand-authored page seeder.
//
//   7. The first segment of @primitive matches the @module's namespace.
//
//   8. Every namespace listed in wiki.config.js has at least one
//      primitive somewhere under lib/.
//
//   9. Every public export in a @module-tagged file's module.exports
//      has a matching @primitive block. Missing blocks become tasks.
//
//  10. @signature parameter count matches the actual function's
//      declared arity. `b.X.Y(opts)` with `function Y()` is a stale
//      signature and fails the gate.
//
//  11. @example bodies parse as valid JavaScript. Syntax errors fail
//      at validation time, not page-render time.
//
//  12. @example bodies contain no unexecutable placeholders:
//      - `// > result`     (use `// → result` per project convention)
//      - `// TODO:`
//      - `// pseudocode`
//      - `<your-X>` / `[REPLACE-ME]` / `... fill this in ...`
//
//  13. @primitive blocks parsed as `proseAfterMultiLine` — prose
//      placed AFTER a multi-line tag (gets swallowed by it).
//
// Run standalone:
//   node examples/wiki/test/validate-source-comment-blocks.js
//   node examples/wiki/test/validate-source-comment-blocks.js --report
//   node examples/wiki/test/validate-source-comment-blocks.js --task-list
//     (writes wiki-migration-tasks.json + prints task summary; exits 0)

var fs   = require("node:fs");
var path = require("node:path");
var vm   = require("node:vm");

var parser       = require("../lib/source-doc-parser");
var optsResolver = require("../lib/opts-resolver");
var curation     = require("../wiki.config");

var LIB_DIR      = path.join(__dirname, "..", "..", "..", "lib");
var SEEDER_INDEX = path.join(__dirname, "..", "seeders", "prod", "pages", "_index");
var TASK_OUT     = path.join(__dirname, "..", "..", "..", "wiki-migration-tasks.json");

var KNOWN_STATUSES = { stable: 1, experimental: 1, deprecated: 1 };
var KNOWN_POSTURES = {
  hipaa: 1, "pci-dss": 1, gdpr: 1, soc2: 1, dora: 1, nis2: 1, cra: 1,
  fapi2: 1, "21-cfr-11": 1, fdx: 1, "tcpa-10dlc": 1, "iab-tcf": 1, "iab-mspa": 1,
  "sox-404": 1, "sec-cyber": 1, ferpa: 1, glba: 1, ccpa: 1, "modpa": 1,
  "nydfs-500": 1, "eu-data-act": 1, "eu-ai-act": 1,
};
var SEMVER_RE = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$/;

// Placeholder patterns in @example bodies that signal unexecutable code.
// Each entry is matched against the example body; a hit becomes a task.
var EXAMPLE_PLACEHOLDERS = [
  { id: "ascii-arrow",   re: /\/\/\s*>\s+/m,                 hint: 'use "// → ..." (Unicode arrow) for expected-result comments — "// > " reads as a shell prompt or shifted-comparison and trips readers' },
  { id: "todo",          re: /\/\/\s*TODO\b/i,               hint: "remove TODO from shipping example or move to internal source comment" },
  { id: "pseudocode",    re: /\/\/\s*pseudocode\b/i,         hint: "examples must be runnable code; remove pseudocode marker" },
  { id: "fill-in",       re: /\.\.\.\s*(fill|replace|your)/i, hint: "concretize the placeholder with a real value" },
  { id: "angle-bracket", re: /<[A-Z][A-Z0-9_-]*>/,           hint: "<PLACEHOLDER> looks like an angle-bracket placeholder — concretize the value" },
  { id: "square-replace", re: /\[\s*REPLACE[-_ ]?ME\s*\]/i,  hint: "replace the [REPLACE-ME] placeholder with a real value" },
];

var REPORT_ONLY = process.argv.indexOf("--report") !== -1;
var TASK_LIST   = process.argv.indexOf("--task-list") !== -1;

function _bare(sig) {
  return String(sig).replace(/\([^)]*\)/g, "").replace(/\s+/g, "").replace(/^b\./, "");
}
function _moduleNs(modTag) {
  return String(modTag || "").replace(/^\s*b\./, "").trim();
}
function _firstSegment(primTag) {
  return _bare(primTag).split(".")[0];
}

// Probe the universe of primitive signatures available for @related
// cross-reference. Sources: every @primitive block under lib/, plus
// every primitive heading in seeded page bodies (which now includes
// hand-authored AND generated pages once the seeder ran).
function _knownPrimitiveSet(docs) {
  var set = {};
  Object.keys(docs).forEach(function (file) {
    docs[file].primitives.forEach(function (p) {
      var sig = p.tags && p.tags.primitive;
      if (sig) set[_bare(sig)] = true;
    });
  });
  try {
    var pages = require(SEEDER_INDEX);
    pages.forEach(function (page) {
      if (!page || typeof page.body !== "string") return;
      var headingRe = /<h[23](?:\s+[^>]*)?>([\s\S]*?)<\/h[23]>/g;
      var m;
      while ((m = headingRe.exec(page.body)) !== null) {
        var inner = m[1].replace(/<[^>]+>/g, "").replace(/&amp;/g, "&");
        var sigRe = /b\.[a-zA-Z][a-zA-Z0-9_.]*/g;
        var sm;
        while ((sm = sigRe.exec(inner)) !== null) set[_bare(sm[0])] = true;
      }
    });
  } catch (_e) { /* non-fatal */ }
  return set;
}

// Extract operator-facing export keys from a source file.
//
// Supports three shapes:
//   1. Object-literal:    module.exports = { foo: foo, bar: bar };
//   2. Per-property:      module.exports.foo = foo;  module.exports.bar = bar;
//   3. Mixed:             both at once.
//
// The object-literal extractor uses bracket-counting (NOT a lazy
// regex) so nested `};` inside method bodies don't terminate the
// scan early. Returns null only when no exports surface at all is
// recoverable (e.g. `module.exports = require('./other')` re-export
// shim — nothing to enumerate).
//
// Underscore-prefixed names are conventionally private — skipped.
function _extractExportKeys(source) {
  var keys = {};

  // Shape 2: per-property module.exports.foo = ...
  var perPropRe = /\bmodule\.exports\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=/g;
  var pm;
  while ((pm = perPropRe.exec(source)) !== null) keys[pm[1]] = true;

  // Shape 1: object-literal module.exports = { ... }
  var openMatch = source.match(/module\.exports\s*=\s*\{/);
  if (openMatch) {
    // Bracket-count from the opening { until matching close.
    var i = openMatch.index + openMatch[0].length;
    var depth = 1;
    var inStr = null;       // null | '"' | "'" | '`'
    var inSlash = false;     // line comment
    var inBlock = false;     // block comment
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
    if (depth === 0) {
      var body = source.slice(openMatch.index + openMatch[0].length, i - 1);
      // Match `name:` or `name,` or `name }` at the start of an
      // object-property position. This is conservative — runs on the
      // body after stripping nested object-literal interiors via a
      // simple depth-aware scan.
      var depth2 = 0;
      var line = "";
      var lines = [];
      for (var j = 0; j < body.length; j++) {
        var ch = body[j];
        if (ch === "{" || ch === "(" || ch === "[") depth2++;
        else if (ch === "}" || ch === ")" || ch === "]") depth2--;
        if (depth2 === 0) {
          line += ch;
          if (ch === "," || ch === "\n") {
            lines.push(line); line = "";
          }
        }
      }
      if (line) lines.push(line);
      lines.forEach(function (l) {
        var lm = l.match(/^\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[:,]/);
        if (lm) keys[lm[1]] = true;
      });
    }
  }

  return Object.keys(keys).filter(function (k) { return !/^_/.test(k); });
}

// Count parameters in a signature like `b.X.Y(a, b, opts?)`. The `?`
// suffix is dropped before counting; trailing-only optional args still
// count toward arity.
function _signatureArity(signature) {
  var m = String(signature).match(/\(([^)]*)\)/);
  if (!m) return 0;
  var inner = m[1].replace(/\s+/g, "");
  if (!inner) return 0;
  return inner.split(",").length;
}

// Find the function declaration for `name` in source and return its
// declared arity. Looks for, in priority order:
//
//   1. Top-level `function NAME(args)` declaration (column 0)
//   2. Top-level `var NAME = function (args)` / `let NAME = ...`
//   3. `module.exports.NAME = function (args)` assignment
//   4. ANY `function NAME(args)` (fallback — may match nested)
//
// Returns -1 if no match. The top-level priority matters for factory
// patterns: `module.exports.create = function (opts) { return function X(req, res, next) {} }`
// — `create` is the operator-facing factory; `X` is the inner middleware.
// Without the priority, the regex matches the inner `function X` first
// (lower in the file is irrelevant — `String.match` finds the FIRST
// occurrence, and `function X` appears AFTER `function (opts)` only if
// that outer is anonymous). Anchoring the top-level pattern to start
// of line (not just `\s+`) discriminates correctly.
function _functionArity(source, name) {
  // 1. Top-level `function NAME(args)` — anchored to BOL.
  var topLevelDecl = new RegExp("^function\\s+" + name + "\\s*\\(([^)]*)\\)", "m");
  // 2. Top-level `var/let/const NAME = function (args)`
  var topLevelVar = new RegExp("^(?:var|let|const)\\s+" + name + "\\s*=\\s*(?:async\\s+)?function\\s*\\(([^)]*)\\)", "m");
  // 3. `module.exports.NAME = (async )?function (args)`
  var exportAssign = new RegExp("module\\.exports\\." + name + "\\s*=\\s*(?:async\\s+)?function\\s*\\(([^)]*)\\)", "m");
  // 4. Fallback: any `function NAME(args)` (may match nested).
  var anyDecl = new RegExp("function\\s+" + name + "\\s*\\(([^)]*)\\)", "m");
  var m = source.match(topLevelDecl)
       || source.match(topLevelVar)
       || source.match(exportAssign)
       || source.match(anyDecl);
  if (!m) return -1;
  var inner = m[1].replace(/\s+/g, "");
  if (!inner) return 0;
  return inner.split(",").length;
}

// Parse-check an @example body. Wrap as an async IIFE so top-level
// `var` / `await` is permitted. Return null on success, error message
// on failure.
function _parseCheckExample(body) {
  var wrapped = "(async function () {\n" + body + "\n})();";
  try {
    new vm.Script(wrapped, { filename: "example.js" });
    return null;
  } catch (e) {
    return (e && e.message) || String(e);
  }
}

function validate() {
  var findings = [];
  var docs = parser.parseTree(LIB_DIR);
  var known = _knownPrimitiveSet(docs);

  var declaredNs = {};
  curation.pages.forEach(function (page) {
    (page.namespaces || []).forEach(function (ns) { declaredNs[ns] = page.slug; });
  });
  var nsHasPrimitive = {};

  Object.keys(docs).forEach(function (file) {
    var rec = docs[file];
    var rel = path.relative(LIB_DIR, file);
    var source = "";
    try { source = fs.readFileSync(file, "utf8"); } catch (_e) { /* continue */ }

    var modNs = rec.module ? _moduleNs(rec.module.tags && rec.module.tags.module) : null;

    // ---- Pass: per-primitive checks ----
    var documentedPrims = {};
    rec.primitives.forEach(function (p) {
      var tags = p.tags || {};
      var primTag = tags.primitive;
      if (!primTag) {
        findings.push({ kind: "schema", file: rel, msg: "@primitive tag is empty" });
        return;
      }
      documentedPrims[_bare(primTag).split(".").pop()] = true;
      // Multi-method signatures: `b.X.a(opts) / b.X.b(opts)` documents
      // both methods in one block. Register every b.* form so the
      // missing-block check doesn't later flag siblings as
      // undocumented.
      if (tags.signature) {
        var sigRe = /b\.[a-zA-Z][a-zA-Z0-9_.]*/g;
        var sm;
        while ((sm = sigRe.exec(tags.signature)) !== null) {
          documentedPrims[_bare(sm[0]).split(".").pop()] = true;
        }
      }

      // 1. shape
      if (!/^b\.[a-zA-Z][a-zA-Z0-9_.]*$/.test(primTag)) {
        findings.push({ kind: "schema", file: rel, primitive: primTag, msg: "@primitive must be `b.X.Y` form" });
      }
      if (!tags.signature) {
        findings.push({ kind: "schema", file: rel, primitive: primTag, msg: "missing @signature" });
      } else if (!/^\s*b\./.test(tags.signature)) {
        findings.push({ kind: "schema", file: rel, primitive: primTag, msg: "@signature must start with `b.`" });
      } else if (_bare(tags.signature) !== _bare(primTag)) {
        var firstSig = String(tags.signature).split(/\s*\/\s*/)[0];
        if (_bare(firstSig) !== _bare(primTag)) {
          findings.push({
            kind: "schema", file: rel, primitive: primTag,
            msg: "@signature first form (`" + firstSig + "`) does not match @primitive",
          });
        }
      }

      if (!p.prose || p.prose.replace(/\s/g, "").length < 12) {
        findings.push({ kind: "schema", file: rel, primitive: primTag, msg: "prose body is empty or too short (<12 non-whitespace chars)" });
      }
      if (p.proseAfterMultiLine) {
        findings.push({
          kind: "ordering", file: rel, primitive: primTag,
          msg: "prose appears AFTER a multi-line tag (@opts/@example/@intro) — those greedily consume every following line. Move prose ABOVE the multi-line tags.",
        });
      }
      if (p.mixedKind) {
        findings.push({
          kind: "schema", file: rel, primitive: primTag,
          msg: "block declares multiple kinds (" + p.mixedKind.join(" + ") + ") — pick exactly one. Parser silently chose `" + p.kind + "`; the others are hidden.",
        });
      }

      var hasExample = (Array.isArray(tags.examples) && tags.examples.length > 0) || tags.exampleFile;
      if (!hasExample) {
        findings.push({ kind: "schema", file: rel, primitive: primTag, msg: "missing @example or @exampleFile" });
      }

      if (tags.status && !KNOWN_STATUSES[tags.status]) {
        findings.push({
          kind: "catalog", file: rel, primitive: primTag,
          msg: "@status must be one of " + Object.keys(KNOWN_STATUSES).join(" / ") + " (got `" + tags.status + "`)",
        });
      }

      if (tags.since && !SEMVER_RE.test(tags.since)) {
        findings.push({
          kind: "catalog", file: rel, primitive: primTag,
          msg: "@since does not look like semver (got `" + tags.since + "`)",
        });
      }

      if (tags.compliance) {
        String(tags.compliance).split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (p2) {
          if (!KNOWN_POSTURES[p2]) {
            findings.push({
              kind: "catalog", file: rel, primitive: primTag,
              msg: "@compliance value `" + p2 + "` not in posture catalog",
            });
          }
        });
      }

      if (tags.related) {
        String(tags.related).split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (refSig) {
          var bare = _bare(refSig);
          // Function-level reference (e.g. b.X.Y): resolved.
          if (known[bare]) return;
          // Namespace-level reference (e.g. b.X with no method): valid
          // when the namespace has at least one documented primitive.
          // Renders as a "see also: this whole namespace" link.
          var refNs = bare.split(".")[0];
          var nsHasAnyDocs = Object.keys(known).some(function (k) {
            return k.split(".")[0] === refNs;
          });
          if (nsHasAnyDocs && bare === refNs) {
            // Bare-namespace ref + namespace IS documented → resolved.
            return;
          }
          // Soft-fail: cross-refs to namespaces with ZERO documented
          // primitives are forward references during the per-namespace
          // migration. The reference is recorded but doesn't fail the
          // gate — it'll resolve naturally once the target namespace
          // gets annotated. Hard-fail only when the target's namespace
          // IS documented but the specific function doesn't exist
          // (real drift).
          if (nsHasAnyDocs) {
            findings.push({
              kind: "cross-ref", file: rel, primitive: primTag,
              msg: "@related `" + refSig + "` — namespace `b." + refNs + "` is documented but this primitive isn't there (drift?)",
            });
          }
          // else: forward reference — silently allowed during migration.
        });
      }

      if (modNs) {
        // Match by PREFIX so a nested @module (e.g. `b.middleware.clearSiteData`)
        // accepts @primitive blocks whose bare path equals the namespace
        // itself (`b.middleware.clearSiteData`) OR descends into it
        // (`b.middleware.clearSiteData.create`). Plain first-segment
        // matching rejects every nested-namespace file.
        var primBare = _bare(primTag);
        if (primBare !== modNs && primBare.indexOf(modNs + ".") !== 0) {
          findings.push({
            kind: "schema", file: rel, primitive: primTag,
            msg: "@primitive namespace `" + primBare + "` does not match the file's @module `" + modNs + "`",
          });
        }
      }

      var ns = _firstSegment(primTag);
      if (declaredNs[ns]) nsHasPrimitive[ns] = true;
      // Nested-namespace match — declared namespaces like
      // `middleware.clearSiteData` / `mail.bimi` / `httpClient.cache`
      // are satisfied by any @primitive whose bare path starts with
      // that namespace. _firstSegment alone returns "middleware" /
      // "mail" / "httpClient" which would never match the dotted form.
      var bare = _bare(primTag);
      Object.keys(declaredNs).forEach(function (declared) {
        if (declared.indexOf(".") === -1) return;       // single-segment handled above
        if (bare === declared || bare.indexOf(declared + ".") === 0) {
          nsHasPrimitive[declared] = true;
        }
      });

      // 9b. Opts must be DOCUMENTED — either via a manual @opts block
      //     OR via the runtime probe (the lib function throws on
      //     unknown keys, letting opts-resolver harvest the allow
      //     list). Pages that ship a primitive with `(opts)` in the
      //     signature but neither manual @opts NOR probe-able opts
      //     would render with no opts section — silent missing
      //     content. No-MVP says: every documented failure mode is
      //     handled; the opts shape IS the failure-mode contract.
      if (tags.signature && /\(\s*[^)]*opts/.test(tags.signature)) {
        if (!tags.opts) {
          var probe = optsResolver.resolve(tags.signature);
          if (!probe.ok) {
            findings.push({
              kind: "opts-undocumented", file: rel, primitive: primTag,
              msg: "@signature takes opts but no @opts block found AND opts-probe failed (" + probe.reason + "). Add a @opts block declaring the typed-object shape so the rendered page shows the opts contract.",
            });
          }
        }
      }

      // 10. Signature/code arity match.
      if (tags.signature && source) {
        var fnName = _bare(primTag).split(".").pop();
        var declaredArity = _functionArity(source, fnName);
        var sigArity = _signatureArity(tags.signature);
        if (declaredArity !== -1 && declaredArity !== sigArity) {
          findings.push({
            kind: "code-mismatch", file: rel, primitive: primTag,
            msg: "@signature shows " + sigArity + " arg(s) but `function " + fnName + "(...)` declares " + declaredArity + " — keep the comment in sync with the code",
          });
        }
      }

      // 11. @example syntax check.
      if (Array.isArray(tags.examples)) {
        tags.examples.forEach(function (ex, i) {
          var err = _parseCheckExample(ex);
          if (err) {
            findings.push({
              kind: "example-syntax", file: rel, primitive: primTag,
              msg: "@example #" + (i + 1) + " fails to parse as JavaScript: " + err,
            });
          }
          // 12. Placeholder detectors.
          EXAMPLE_PLACEHOLDERS.forEach(function (det) {
            if (det.re.test(ex)) {
              findings.push({
                kind: "example-placeholder", file: rel, primitive: primTag,
                msg: "@example #" + (i + 1) + " contains `" + det.id + "` placeholder — " + det.hint,
              });
            }
          });
        });
      }
    });

    // ---- Pass: @module metadata completeness ----
    // Every @module block with at least one @primitive block should
    // also declare @nav (sidebar group) and @card (home-page card
    // description). Without them the namespace lands in the "Other"
    // group with no card — visible but ungrouped. Surface as a finding
    // so new annotations can't drift into "Other" silently.
    if (rec.module && rec.primitives.length > 0) {
      var modTags = rec.module.tags || {};
      if (!modTags.nav) {
        findings.push({
          kind: "metadata", file: rel, primitive: "@module b." + modNs,
          msg: "@module block lacks @nav — namespace will land in the catch-all 'Other' sidebar group. Add `@nav <GroupName>` (e.g. Tools / Validation / HTTP / Crypto / Identity / Communication / Compliance / Production / AI / Network / Observability).",
        });
      }
      if (!modTags.card) {
        findings.push({
          kind: "metadata", file: rel, primitive: "@module b." + modNs,
          msg: "@module block lacks @card — namespace won't render a card on the home page. Add a `@card` block with a 1-2 sentence description.",
        });
      }
      if (!modTags.title) {
        findings.push({
          kind: "metadata", file: rel, primitive: "@module b." + modNs,
          msg: "@module block lacks @title — sidebar label defaults to `b." + modNs + "`. Add `@title <Display Name>` (e.g. `CSV` / `Database` / `Audit Chain`).",
        });
      }
    }

    // ---- Pass: every FUNCTION export has a @primitive block ----
    // Non-function exports (regex constants, error classes, plain
    // objects) aren't operator-facing primitives — they're either
    // documented under their own namespace (Error classes appear in
    // the error-catalog harvester) or they're configuration values.
    // The check fires only when the source has an actual
    // `function NAME(...)` declaration matching the export key.
    if (modNs && source) {
      var exports = _extractExportKeys(source);
      if (exports) {
        // When the namespace's @primitive sits directly above
        // `function create(opts)` (the factory-pattern middleware
        // shape — `b.middleware.csrfProtect` documented at the
        // namespace level, exported as `{ create }`), accept the
        // namespace-level @primitive block as documenting the create
        // export. Operators call `b.middleware.X(opts)` — the create
        // function IS the namespace.
        var hasNsLevelPrimitive = rec.primitives.some(function (p) {
          var primBare = _bare(p.tags && p.tags.primitive);
          return primBare === modNs;
        });
        exports.forEach(function (k) {
          if (documentedPrims[k]) return;
          if (hasNsLevelPrimitive && k === "create") return;
          // Only require a @primitive block when the export is a
          // FUNCTION (operator-facing primitive). Skip constants /
          // regex / classes.
          var arity = _functionArity(source, k);
          if (arity === -1) return;
          findings.push({
            kind: "missing-block", file: rel, primitive: "b." + modNs + "." + k,
            msg: "module exports function `" + k + "` but no @primitive block documents it — add one before `function " + k + "`",
          });
        });
      }
    }
  });

  Object.keys(declaredNs).forEach(function (ns) {
    if (!nsHasPrimitive[ns]) {
      findings.push({
        kind: "curation", file: "wiki.config.js",
        primitive: "(curation namespace `" + ns + "` -> page `" + declaredNs[ns] + "`)",
        msg: "no @primitive blocks found anywhere under lib/ for declared namespace `" + ns + "`",
      });
    }
  });

  return findings;
}

function _emitTaskList(findings) {
  var grouped = {};
  findings.forEach(function (f) {
    var key = f.file + (f.primitive ? ":" + f.primitive : "");
    if (!grouped[key]) grouped[key] = { file: f.file, primitive: f.primitive || null, issues: [] };
    grouped[key].issues.push({ kind: f.kind, msg: f.msg });
  });
  var tasks = Object.keys(grouped).map(function (k, i) {
    return Object.assign({ id: i + 1 }, grouped[k]);
  });
  fs.writeFileSync(TASK_OUT, JSON.stringify({ generatedAt: new Date().toISOString(), taskCount: tasks.length, tasks: tasks }, null, 2));
  console.log("[validate-source-comment-blocks] wrote " + tasks.length + " task(s) to " + path.relative(process.cwd(), TASK_OUT));
  // Group summary by kind for the operator.
  var byKind = {};
  findings.forEach(function (f) { byKind[f.kind] = (byKind[f.kind] || 0) + 1; });
  console.log("by kind:");
  Object.keys(byKind).sort().forEach(function (k) { console.log("  " + k.padEnd(22) + " " + byKind[k]); });
}

function _report(findings) {
  if (TASK_LIST) {
    _emitTaskList(findings);
    return 0;
  }
  if (findings.length === 0) {
    console.log("[validate-source-comment-blocks] OK - no findings");
    return 0;
  }
  console.log("[validate-source-comment-blocks] " + findings.length + " finding(s):");
  findings.forEach(function (f, i) {
    console.log("  " + (i + 1) + ". [" + f.kind + "] " + f.file + (f.primitive ? " :: " + f.primitive : ""));
    console.log("     " + f.msg);
  });
  return REPORT_ONLY ? 0 : 1;
}

if (require.main === module) {
  process.exit(_report(validate()));
}

module.exports = { validate: validate };
