"use strict";
// source-comment-block-validator — shared validation engine for the
// source-driven wiki pipeline (`@module` + `@primitive` blocks in
// lib/*.js).
//
// The same logic was historically inlined in
// examples/wiki/test/validate-source-comment-blocks.js — the wiki-e2e
// gate — and that's where CI runs it. To let the same checks run in
// the framework's static-gates step (the cheap-pre-smoke phase), the
// engine moved here and both consumers import it:
//
//   1. examples/wiki/test/validate-source-comment-blocks.js
//        — wiki-e2e entry; CI invokes it. Keeps the historical
//          --report / --task-list flags and the exit-on-finding
//          behavior expected by .github/workflows/ci.yml.
//
//   2. scripts/validate-source-comment-blocks.js
//        — framework-level static gate. Runs from a clean checkout
//          without `examples/wiki && npm install`. opts-resolver
//          (which loads @blamejs/core to probe runtime opt allow-
//          lists) is optional here — when @blamejs/core isn't on
//          require.resolve, the opts-undocumented check is skipped
//          rather than blocking the gate.
//
// The validate() entry takes a config object:
//
//   {
//     libDir:           absolute path to framework lib/
//     curationPages:    array of page descriptors from wiki.config.js;
//                       empty array is acceptable
//     parser:           required - the source-doc-parser module
//     optsResolver:     optional - opts-resolver module; when absent
//                       the opts-undocumented check is skipped
//     seederIndex:      optional - absolute path to a seeded-pages
//                       module exporting [{ body }]; used to discover
//                       primitive headings in hand-authored seeders
//                       so @related cross-refs resolve
//   }
//
// Returns an array of finding objects:
//   { kind, file, primitive?, msg }
//
// Pure module — no side effects at require-time. Boots in <50ms.

var fs   = require("node:fs");
var path = require("node:path");
var vm   = require("node:vm");

var KNOWN_STATUSES = { stable: 1, experimental: 1, deprecated: 1 };
var KNOWN_POSTURES = {
  hipaa: 1, "pci-dss": 1, gdpr: 1, soc2: 1, dora: 1, nis2: 1, cra: 1,
  fapi2: 1, "21-cfr-11": 1, fdx: 1, "tcpa-10dlc": 1, "iab-tcf": 1, "iab-mspa": 1,
  "sox-404": 1, "sec-cyber": 1, ferpa: 1, glba: 1, ccpa: 1, "modpa": 1,
  "ca-sopipa": 1, coppa: 1, "coppa-2025": 1,
  "nydfs-500": 1, "eu-data-act": 1, "eu-ai-act": 1,
  dsa: 1, "pipl-cn": 1,
  // v0.10.8 — EU AI Act Art. 50 + Art. 11 + AB-853 + CAC + AI governance
  "eu-ai-act-art-50": 1, "eu-ai-act-art-11": 1,
  "ca-ab-853": 1, "ca-sb-942": 1,
  "nyc-ll144": 1, "ca-tfaia": 1,
  "cac-genai-label": 1,
  "nist-ai-600-1": 1, "nist-ai-rmf": 1,
  "iso-42001": 1, "iso-23894": 1,
};
var SEMVER_RE = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$/;

// Placeholder patterns in @example bodies that signal unexecutable code.
// Each entry is matched against the example body; a hit becomes a task.
var EXAMPLE_PLACEHOLDERS = [
  { id: "ascii-arrow",    re: /\/\/\s*>\s+/m,                  hint: 'use "// → ..." (Unicode arrow) for expected-result comments — "// > " reads as a shell prompt or shifted-comparison and trips readers' },
  // Split the literal so this detector's own source doesn't trip the
  // wiki-gate's own TO+DO-marker scan against this very file.
  { id: "todo",           re: new RegExp("\\/\\/\\s*TO" + "DO\\b", "i"),  hint: "remove placeholder markers from shipping examples" },  // allow:dynamic-regex — pattern is constructed from in-file literals only; no operator input
  { id: "pseudocode",     re: /\/\/\s*pseudocode\b/i,          hint: "examples must be runnable code; remove pseudocode marker" },
  { id: "fill-in",        re: /\.\.\.\s*(fill|replace|your)/i, hint: "concretize the placeholder with a real value" },
  { id: "angle-bracket",  re: /<[A-Z][A-Z0-9_-]*>/,            hint: "<PLACEHOLDER> looks like an angle-bracket placeholder — concretize the value" },
  { id: "square-replace", re: /\[\s*REPLACE[-_ ]?ME\s*\]/i,    hint: "replace the [REPLACE-ME] placeholder with a real value" },
];

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
// every primitive heading in seeded page bodies (which includes
// hand-authored AND generated pages once the seeder ran), plus the
// factory-synthesized ABI methods (compliancePosture / buildProfile /
// loadRulePack / gate) every defineGuard / defineParser guard exposes —
// these have no in-source @primitive block (the doc lives once in
// gate-contract.js's @abiTemplate blocks) but the page generator renders
// them per guard, so a real guard block's @related to them must resolve.
function _knownPrimitiveSet(docs, seederIndex, parser) {
  var set = {};
  Object.keys(docs).forEach(function (file) {
    docs[file].primitives.forEach(function (p) {
      var sig = p.tags && p.tags.primitive;
      if (sig) set[_bare(sig)] = true;
    });
  });
  // Register the per-guard ABI method sigs the factory synthesizes.
  if (parser && typeof parser.factoryTemplates === "function") {
    var templates = parser.factoryTemplates(docs);
    Object.keys(docs).forEach(function (file) {
      var rec = docs[file];
      if (!rec.factory) return;
      var ns = rec.module && rec.module.tags
        ? _moduleNs(rec.module.tags.module)
        : null;
      if (!ns) return;
      (templates[rec.factory.kind] || []).forEach(function (tpl) {
        var method = tpl.tags && tpl.tags.method;
        if (method) set[ns + "." + method] = true;
      });
    });
  }
  if (seederIndex) {
    try {
      var pages = require(seederIndex);
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
    } catch (_e) { /* non-fatal — seeder index optional */ }
  }
  return set;
}

// Extract operator-facing export keys from a source file.
//
// Supports three shapes:
//   1. Object-literal:    module dot exports = { foo: foo, bar: bar };
//   2. Per-property:      module dot exports dot foo = foo;
//   3. Mixed:             both at once.
//
// The object-literal extractor uses bracket-counting (NOT a lazy
// regex) so nested closing braces inside method bodies don't terminate
// the scan early. Returns the discovered key set; underscore-prefixed
// names are conventionally private and skipped.
function _extractExportKeys(source) {
  var keys = {};

  // Shape A: per-property module.exports.foo = ...
  var perPropRe = /\bmodule\.exports\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=/g;
  var pm;
  while ((pm = perPropRe.exec(source)) !== null) keys[pm[1]] = true;

  // Shape B: object literal `module.exports = {`.  Shape C: factory call
  // `module.exports = [ns.]defineGuard({` / `defineParser({` — the guard
  // family's consolidated wiring assembles the frozen exports object inside
  // gateContract.defineGuard/defineParser, so there is no object literal to
  // scan. Both forms open an object whose keys we collect identically; the
  // factory form additionally yields the per-guard FUNCTION exports it wires
  // in (the spec's `validate` / `sanitize` / `gate` / `entry` references and
  // any functions passed through `extra: { ... }`). The factory-generated
  // wiring (buildProfile / compliancePosture / loadRulePack / gate default)
  // has no in-source `function NAME`, so the arity filter in the missing-block
  // pass skips it — but a per-guard function the author forgot to document is
  // still caught, so the doc gate survives the factory refactor.
  var litMatch = source.match(/module\.exports\s*=\s*\{/);
  var factoryMatch = source.match(/module\.exports\s*=\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*\.)?define(?:Guard|Parser)\s*\(\s*\{/);
  var openIdx = -1;
  var factoryMode = false;
  if (litMatch) {
    openIdx = litMatch.index + litMatch[0].length - 1;
  } else if (factoryMatch) {
    openIdx = factoryMatch.index + factoryMatch[0].lastIndexOf("{");
    factoryMode = true;
  }
  if (openIdx >= 0) {
    _collectObjectKeys(source, openIdx, factoryMode).forEach(function (k) { keys[k] = true; });
  }

  return Object.keys(keys).filter(function (k) { return !/^_/.test(k); });
}

// Bracket-count the object literal whose opening `{` is at openIdx and return
// its top-level property names. In factoryMode it also returns bare-identifier
// property VALUES (e.g. `entry: validate` -> `validate`, the exported function
// the spec references) and the keys/values of a nested `extra: { ... }` map.
// The missing-block pass arity-filters the result, so non-function names
// (NAME / PROFILES / error classes) are harmless.
function _collectObjectKeys(source, openIdx, factoryMode) {
  var i = openIdx + 1;
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
  var found = [];
  if (depth !== 0) return found;
  var body = source.slice(openIdx + 1, i - 1);
  // Match `name:` or `name,` at the start of an object-property position,
  // after stripping nested object/array/call interiors via a depth scan.
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
    if (lm) found.push(lm[1]);
    if (factoryMode) {
      var vm = l.match(/:\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*,?\s*$/);
      if (vm) found.push(vm[1]);
    }
  });
  if (factoryMode) {
    var em = body.match(/(^|[\s,{])extra\s*:\s*\{/);
    if (em) {
      _collectObjectKeys(body, em.index + em[0].lastIndexOf("{"), true).forEach(function (k) {
        found.push(k);
      });
    }
  }
  return found;
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
// patterns where the namespace's create() returns an inner middleware
// function — without the priority, the regex matches the inner
// `function X` and reports the wrong arity. Anchoring the top-level
// pattern to start of line (not just `\s+`) discriminates correctly.
function _functionArity(source, name) {
  // Name comes from the @primitive tag's source-doc-parser-validated
  // identifier (alphanumeric + underscore); the constructed patterns
  // can't carry operator-controlled regex metacharacters.
  // 1. Top-level `function NAME(args)` — anchored to BOL.
  var topLevelDecl = new RegExp("^function\\s+" + name + "\\s*\\(([^)]*)\\)", "m");  // allow:dynamic-regex — `name` is alphanumeric + underscore per the @primitive tag schema; no operator input
  // 2. Top-level `var/let/const NAME = function (args)`
  var topLevelVar = new RegExp("^(?:var|let|const)\\s+" + name + "\\s*=\\s*(?:async\\s+)?function\\s*\\(([^)]*)\\)", "m");  // allow:dynamic-regex — same name source
  // 3. `module.exports.NAME = (async )?function (args)`
  var exportAssign = new RegExp("module\\.exports\\." + name + "\\s*=\\s*(?:async\\s+)?function\\s*\\(([^)]*)\\)", "m");  // allow:dynamic-regex — same name source
  // 4. Fallback: any `function NAME(args)` (may match nested).
  var anyDecl = new RegExp("function\\s+" + name + "\\s*\\(([^)]*)\\)", "m");  // allow:dynamic-regex — same name source
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

// validate(config) → findings[]
//
// Pure function. Same checks as the historical wiki-e2e validator.
// optsResolver is optional; when absent, the opts-undocumented gate
// (#9b) silently skips — every other check still runs.
function validate(config) {
  if (!config || !config.libDir) throw new TypeError("validate(): config.libDir is required");
  if (!config.parser) throw new TypeError("validate(): config.parser is required");

  var libDir       = config.libDir;
  var parser       = config.parser;
  var optsResolver = config.optsResolver || null;
  var seederIndex  = config.seederIndex || null;
  var curationPages = Array.isArray(config.curationPages) ? config.curationPages : [];

  var findings = [];
  var docs = parser.parseTree(libDir);
  var known = _knownPrimitiveSet(docs, seederIndex, parser);

  var declaredNs = {};
  curationPages.forEach(function (page) {
    (page.namespaces || []).forEach(function (ns) { declaredNs[ns] = page.slug; });
  });
  var nsHasPrimitive = {};

  Object.keys(docs).forEach(function (file) {
    var rec = docs[file];
    var rel = path.relative(libDir, file);
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

      if (tags.since && (tags.since.length > 32 || !SEMVER_RE.test(tags.since))) {                   // allow:regex-no-length-cap — length-bounded inline / allow:raw-byte-literal — semver string max length, not bytes
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
      //
      //     When optsResolver is unavailable (framework-level static
      //     gate runs from a clean checkout without
      //     `examples/wiki && npm install`), the probe-side check
      //     skips. The manual @opts check above still fires.
      if (tags.signature && /\(\s*[^)]*opts/.test(tags.signature)) {
        if (!tags.opts && optsResolver) {
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
      var exportKeys = _extractExportKeys(source);
      if (exportKeys) {
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
        exportKeys.forEach(function (k) {
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

  // ---- Pass: @abiTemplate structural checks ----
  // ABI doc templates are single-sourced placeholder blocks (b.{NS}.<method>
  // with {NS}/{ERR} substituted per guard at page-gen time). They are NOT
  // resolvable primitives, so the per-primitive pass skips them (the parser
  // routes them to rec.abiTemplates, not rec.primitives). Validate their
  // template shape instead: a known factory kind, a @method, a placeholder
  // @signature, valid @status, real prose, and at least one @example. The
  // placeholder sig + placeholder @example bodies are intentional, so the
  // resolvable-primitive / JS-parse passes do not apply.
  Object.keys(docs).forEach(function (file) {
    var rec = docs[file];
    if (!rec.abiTemplates || rec.abiTemplates.length === 0) return;
    var rel = path.relative(libDir, file);
    var seen = {};
    rec.abiTemplates.forEach(function (t) {
      var tags = t.tags || {};
      var kind = tags.abiTemplate;
      var label = "@abiTemplate " + (kind || "?") + (tags.method ? " " + tags.method : "");
      if (kind !== "defineGuard" && kind !== "defineParser") {
        findings.push({
          kind: "abi-template", file: rel, primitive: label,
          msg: "@abiTemplate value must be `defineGuard` or `defineParser` (got `" + kind + "`)",
        });
      }
      if (!tags.method) {
        findings.push({
          kind: "abi-template", file: rel, primitive: label,
          msg: "@abiTemplate block lacks @method — name the factory-generated ABI method it documents",
        });
      } else {
        var dupeKey = kind + "::" + tags.method;
        if (seen[dupeKey]) {
          findings.push({
            kind: "abi-template", file: rel, primitive: label,
            msg: "duplicate @abiTemplate for " + dupeKey + " — one template per (factory, method)",
          });
        }
        seen[dupeKey] = true;
      }
      if (!tags.signature) {
        findings.push({
          kind: "abi-template", file: rel, primitive: label,
          msg: "@abiTemplate block lacks @signature",
        });
      } else if (tags.signature.indexOf("{NS}") === -1) {
        findings.push({
          kind: "abi-template", file: rel, primitive: label,
          msg: "@abiTemplate @signature must carry the `{NS}` placeholder (got `" + tags.signature + "`)",
        });
      } else if (tags.method && _bareTemplateMethod(tags.signature) !== tags.method) {
        findings.push({
          kind: "abi-template", file: rel, primitive: label,
          msg: "@abiTemplate @signature method `" + _bareTemplateMethod(tags.signature) + "` does not match @method `" + tags.method + "`",
        });
      }
      if (tags.status && !KNOWN_STATUSES[tags.status]) {
        findings.push({
          kind: "abi-template", file: rel, primitive: label,
          msg: "@abiTemplate @status must be one of " + Object.keys(KNOWN_STATUSES).join(" / ") + " (got `" + tags.status + "`)",
        });
      }
      if (tags.compliance) {
        String(tags.compliance).split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (p2) {
          if (!KNOWN_POSTURES[p2]) {
            findings.push({
              kind: "abi-template", file: rel, primitive: label,
              msg: "@abiTemplate @compliance value `" + p2 + "` not in posture catalog",
            });
          }
        });
      }
      if (!t.prose || t.prose.replace(/\s/g, "").length < 12) {
        findings.push({
          kind: "abi-template", file: rel, primitive: label,
          msg: "@abiTemplate prose body is empty or too short (<12 non-whitespace chars)",
        });
      }
      if (t.proseAfterMultiLine) {
        findings.push({
          kind: "abi-template", file: rel, primitive: label,
          msg: "prose appears AFTER a multi-line tag (@opts/@example) — move prose ABOVE the multi-line tags",
        });
      }
      if (!Array.isArray(tags.examples) || tags.examples.length === 0) {
        findings.push({
          kind: "abi-template", file: rel, primitive: label,
          msg: "@abiTemplate block lacks @example",
        });
      }
    });
  });

  return findings;
}

// Extract the bare method name from a placeholder template signature like
// `b.{NS}.compliancePosture(name)` → `compliancePosture`.
function _bareTemplateMethod(sig) {
  var m = String(sig).replace(/\([^)]*\)/g, "").match(/\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*$/);
  return m ? m[1] : null;
}

module.exports = {
  validate:           validate,
  KNOWN_STATUSES:     KNOWN_STATUSES,
  KNOWN_POSTURES:     KNOWN_POSTURES,
  EXAMPLE_PLACEHOLDERS: EXAMPLE_PLACEHOLDERS,
};
