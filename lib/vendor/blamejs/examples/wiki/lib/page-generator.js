"use strict";
// page-generator — produces { slug, title, body } page objects from
// source-doc-parser output + a curation manifest.
//
// Pipeline:
//   1. Parser walks framework lib/ and returns { module, primitives }
//      records keyed by file path.
//   2. Curation manifest (wiki.config.js) declares pages — each page
//      lists which namespaces it covers, an intro override, ordering
//      hints, and hidden-primitive denylist.
//   3. Generator merges: every page's intro is the union of (curation
//      override → module @intro for the first listed namespace), and
//      its body is one section() call per primitive in declared order.
//
// Output shape matches the legacy hand-authored seeders so the
// migrations seeder consumes either flavor without code changes.
//
// The generator is run at seed time by the migrations runner — no
// pre-build step. Lib edits land instantly in the next `npm start`.

var section = require("./section");
var parser = require("./source-doc-parser");

// Build a sig → page-href resolver from the curation manifest + parsed
// docs. Every @primitive in a curated namespace maps to its rendered
// page slug + section anchor, so @related cross-references in the
// rendered HTML jump straight to the right section instead of routing
// through the /api catch-all.
//
// Usage:
//   var resolve = _buildSignatureResolver(curation, docsByPath);
//   resolve("b.uuid.v4")          → "/uuid#uuid-v4"
//   resolve("b.guardCsv.gate")    → "/api#guardcsv-gate"   (fallback)
function _buildSignatureResolver(curation, docsByPath) {
  // Map: bare-signature ("uuid.v4") → page slug.
  var nsToPageSlug = {};
  curation.pages.forEach(function (spec) {
    if (Array.isArray(spec.namespaces)) {
      spec.namespaces.forEach(function (ns) { nsToPageSlug[ns] = spec.slug; });
    }
  });
  // Map: bare-signature → { page, anchor }.
  var bySig = {};
  Object.keys(docsByPath).forEach(function (file) {
    (docsByPath[file].primitives || []).forEach(function (p) {
      var sig = p.tags && p.tags.primitive;
      if (!sig) return;
      var bare = String(sig).replace(/^b\./, "");
      var ns = bare.split(".")[0];
      var slug = nsToPageSlug[ns];
      if (!slug) return;       // namespace not curated — caller falls back to /api
      var anchor = (p.tags && p.tags.anchor) || section._slugFromSignature(sig);
      bySig[bare] = { page: slug, anchor: anchor };
    });
  });
  return function resolve(refSig) {
    var bare = String(refSig).replace(/<\/?code>/g, "").replace(/^\s*b\./, "").replace(/\([^)]*\)/g, "").replace(/\s+/g, "");
    var hit = bySig[bare];
    if (hit) return "/" + hit.page + "#" + hit.anchor;
    // Fallback: deep-link into the /api index.
    var apiAnchor = section._slugFromSignature(refSig);
    return "/api#" + apiAnchor;
  };
}

// Convert markdown-ish tokens in prose to HTML.
//
// Supported syntax (kept deliberately small — authors write docstring
// prose, not full markdown):
//
//   - blank-line-separated paragraphs       → <p>...</p>
//   - inline `backtick code`                → <code>...</code>
//   - ```language\n...\n``` fenced blocks   → <pre><code class="language-X">...</code></pre>
//   - bullet lists ("- foo" / "* foo")      → <ul><li>...</li></ul>
//
// Existing HTML in the prose passes through untouched (authors can
// drop a <table> / <aside> / etc. when needed).
function _proseToHtml(prose) {
  if (!prose) return "";
  var src = String(prose);
  // First pass: extract fenced code blocks and replace with sentinels
  // so the paragraph splitter doesn't treat newlines inside them as
  // paragraph boundaries.
  var fences = [];
  src = src.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, function (_m, lang, body) {
    var idx = fences.length;
    var cls = lang ? ' class="language-' + lang + '"' : "";
    fences.push('<pre><code' + cls + '>' + _esc(body.replace(/\n+$/, "")) + "</code></pre>");
    return "\n\nFENCE" + idx + "\n\n";
  });

  var blocks = src.split(/\n\s*\n/).map(function (b) { return b.replace(/^\s+|\s+$/g, ""); }).filter(Boolean);
  return blocks.map(function (block) {
    // Restore fenced blocks unchanged.
    var fenceMatch = block.match(/^FENCE(\d+)$/);
    if (fenceMatch) return fences[parseInt(fenceMatch[1], 10)];

    // Bullet lists: every line begins with "- " or "* ".
    var lines = block.split("\n").map(function (l) { return l.replace(/^\s+|\s+$/g, ""); });
    var allBullets = lines.length > 0 && lines.every(function (l) { return /^[-*]\s+/.test(l); });
    if (allBullets) {
      var items = lines.map(function (l) {
        var body = l.replace(/^[-*]\s+/, "");
        return "<li>" + _inlineCode(body) + "</li>";
      });
      return "<ul>" + items.join("\n") + "</ul>";
    }

    // Default: collapse internal newlines to spaces, wrap in <p>.
    var single = block.replace(/\n/g, " ");
    return "<p>" + _inlineCode(single) + "</p>";
  }).join("\n");
}

function _inlineCode(s) {
  return String(s).replace(/`([^`]+)`/g, function (_m, body) {
    return "<code>" + body + "</code>";
  });
}

// Minimal HTML escape for fenced-code body content. Authors expect
// their literal `<` / `>` / `&` in code samples to render verbatim.
function _esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Pull the namespace ("csv" / "uuid" / etc.) from a primitive signature.
// Returns the FIRST dotted segment after `b.` for legacy single-segment
// namespaces. Use _nsOfWithin for nested-namespace pages (where the
// curation declares e.g. `middleware.clearSiteData` and the primitive
// lives at `b.middleware.clearSiteData`).
function _nsOf(sig) {
  var m = String(sig).match(/^\s*b\.([a-zA-Z0-9_]+)/);
  return m ? m[1] : null;
}

// Resolve a primitive signature's namespace within the curation's
// declared namespace set — picks the LONGEST matching prefix so a
// page declaring `middleware.clearSiteData` collects every primitive
// under that nested namespace AND a page declaring `middleware`
// (parent) doesn't accidentally swallow them. Returns null when no
// declared namespace matches.
function _nsOfWithin(sig, declaredNamespaces) {
  var bare = String(sig).replace(/\([^)]*\)/g, "").replace(/\s+/g, "")
    .replace(/^b\./, "");
  var best = null;
  for (var i = 0; i < declaredNamespaces.length; i += 1) {
    var ns = declaredNamespaces[i];
    if (bare === ns || bare.indexOf(ns + ".") === 0) {
      if (!best || ns.length > best.length) best = ns;
    }
  }
  return best;
}

// Turn a parser primitive record into a section() call. The opts block
// auto-resolves via opts-resolver; the example pulls inline @example
// or @exampleFile (snippets/<path>).
//
// `resolveRelated` (optional) is a sig → href resolver — when set,
// the rendered Related footer's links jump straight to the right
// page+anchor instead of routing through /api.
function _renderPrimitive(prim, resolveRelated) {
  var tags = prim.tags || {};
  var signature = tags.signature || tags.primitive;
  if (!signature) return "";
  var prose = _proseToHtml(prim.prose);
  if (!prose) prose = "<p>" + (tags.primitive || "") + "</p>";

  // Examples: @example wins (one or many), then @exampleFile.
  var example = null;
  var exampleLang = "javascript";
  if (Array.isArray(tags.examples) && tags.examples.length > 0) {
    // Multiple inline examples → concatenate with a comment separator;
    // section() renders the concatenation as one block. Authors can
    // split with blank lines inside @example for visual breaks.
    example = tags.examples.join("\n\n");
  } else if (tags.exampleFile) {
    example = tags.exampleFile;
  }

  // opts resolution priority:
  //   1. Author-supplied @opts block — manual declaration; wins when
  //      the probe can't reach truth (e.g. b.uuid.v7's opts? path).
  //   2. "auto" — probe the lib via opts-resolver. Emits the typed
  //      block when probe succeeds; emits NOTHING when probe fails
  //      (resilience: ugly placeholders are worse than missing blocks).
  //   3. Skip entirely when the signature has no opts parameter.
  var optsArg;
  if (tags.opts) {
    // @opts ships its own typed-object body. The parser already
    // dedented the multi-line value (so author-side comment indentation
    // doesn't leak through); we re-indent every body line by two
    // spaces so the rendered block looks like a properly indented
    // typed object instead of flush-left keys.
    var optsBody = String(tags.opts)
      .split("\n")
      .map(function (l) { return l.length ? "  " + l : l; })
      .join("\n");
    optsArg = "<pre><code class=\"language-javascript\">{\n" + optsBody + "\n}</code></pre>";
  } else if (!/\(\s*[^)]*opts/.test(signature)) {
    optsArg = false;
  } else {
    optsArg = "auto";
  }

  var compliance = null;
  if (tags.compliance) {
    compliance = String(tags.compliance).split(",").map(function (s) {
      return s.trim();
    }).filter(Boolean);
  }
  var related = null;
  if (tags.related) {
    related = String(tags.related).split(",").map(function (s) {
      return s.trim();
    }).filter(Boolean);
  }

  return section.section({
    signature:      signature,
    prose:          prose,
    opts:           optsArg,
    example:        example,
    exampleLang:    exampleLang,
    since:          tags.since || null,
    status:         tags.status || null,
    compliance:     compliance,
    related:        related,
    resolveRelated: resolveRelated,
    anchor:         tags.anchor || null,
    headingTag:     tags.headingTag || "h3",
  });
}

// Build a generated page object.
//
// pageSpec: {
//   slug:        "csv-uuid-slug",
//   title:       "Format helpers (generated)",
//   namespaces:  ["csv", "uuid", "slug"],   // primitives belonging to these b.X
//   intro:       "<p>Optional override prose</p>",  // optional
//   order:       ["b.csv.parse", "b.csv.stringify", ...], // optional explicit order
//   hidden:      ["b.csv._internal"],       // optional denylist
//   ns_h2:       true,                      // emit <h2> divider per namespace
// }
//
// docsByPath: output of source-doc-parser.parseTree(libDir).
// resolveRelated: optional sig → href resolver from generateAll.
function generatePage(pageSpec, docsByPath, resolveRelated) {
  if (!pageSpec || !pageSpec.slug) throw new TypeError("generatePage: pageSpec.slug required");
  var nsList = Array.isArray(pageSpec.namespaces) ? pageSpec.namespaces : [];
  var order = Array.isArray(pageSpec.order) ? pageSpec.order : [];
  var hidden = Array.isArray(pageSpec.hidden) ? pageSpec.hidden : [];
  var hiddenSet = {};
  for (var h = 0; h < hidden.length; h++) hiddenSet[hidden[h]] = true;

  // Group primitives by namespace, drop hidden ones.
  var byNs = {};
  var moduleByNs = {};
  var paths = Object.keys(docsByPath);
  for (var p = 0; p < paths.length; p++) {
    var rec = docsByPath[paths[p]];
    if (rec.module && rec.module.tags && rec.module.tags.module) {
      var modSig = rec.module.tags.module.replace(/^\s*b\./, "");
      moduleByNs[modSig] = rec.module;
    }
    for (var i = 0; i < rec.primitives.length; i++) {
      var prim = rec.primitives[i];
      var primSig = (prim.tags && prim.tags.primitive) || "";
      if (hiddenSet[primSig]) continue;
      // Match against the curation's declared namespace list so a
      // page declaring `middleware.clearSiteData` collects every
      // primitive under that nested namespace.
      var ns = _nsOfWithin(primSig, nsList);
      if (!ns) continue;
      if (!byNs[ns]) byNs[ns] = [];
      byNs[ns].push(prim);
    }
  }

  // Order primitives within each namespace: explicit `order` first, then
  // the rest in source order.
  var orderIdx = {};
  for (var o = 0; o < order.length; o++) orderIdx[order[o]] = o;
  for (var nKey in byNs) {
    if (!Object.prototype.hasOwnProperty.call(byNs, nKey)) continue;
    byNs[nKey].sort(function (a, b) {
      var aSig = (a.tags && a.tags.primitive) || "";
      var bSig = (b.tags && b.tags.primitive) || "";
      var aIdx = orderIdx[aSig];
      var bIdx = orderIdx[bSig];
      if (aIdx !== undefined && bIdx !== undefined) return aIdx - bIdx;
      if (aIdx !== undefined) return -1;
      if (bIdx !== undefined) return 1;
      return 0;
    });
  }

  // Build body: title H1, intro, then per-namespace sections.
  var lines = [];
  lines.push('<h1>' + pageSpec.title + '</h1>');

  if (pageSpec.intro) {
    lines.push(pageSpec.intro);
  } else {
    // Use the @intro of the FIRST namespace's @module block if present.
    for (var n0 = 0; n0 < nsList.length; n0++) {
      var modRec = moduleByNs[nsList[n0]];
      if (modRec && modRec.tags && modRec.tags.intro) {
        lines.push(_proseToHtml(modRec.tags.intro));
        break;
      }
    }
  }

  for (var ni = 0; ni < nsList.length; ni++) {
    var ns2 = nsList[ni];
    var prims = byNs[ns2] || [];
    if (prims.length === 0) continue;
    if (pageSpec.ns_h2 || nsList.length > 1) {
      lines.push(section.h2({ title: "b." + ns2 }));
      // If this namespace's @module has its own @intro AND we already
      // used the first-ns intro at the top, this one becomes a per-h2
      // intro. Skip when ni === 0 unless the page used a curation intro.
      var modRec2 = moduleByNs[ns2];
      var skipNsIntro = (ni === 0 && !pageSpec.intro);
      if (!skipNsIntro && modRec2 && modRec2.tags && modRec2.tags.intro) {
        lines.push(_proseToHtml(modRec2.tags.intro));
      }
    }
    for (var pi = 0; pi < prims.length; pi++) {
      lines.push(_renderPrimitive(prims[pi], resolveRelated));
    }
  }

  return {
    slug:  pageSpec.slug,
    title: pageSpec.title,
    body:  lines.join("\n"),
    // generated marker — handy for tooling that wants to distinguish
    // hand-authored vs. generated pages.
    generated: true,
  };
}

// Build a generated CONCEPT page from a @concept block.
//
// pageSpec: {
//   slug:    "concepts-security-defaults",
//   concept: "security-defaults",   // matches @concept tag value
// }
function generateConceptPage(pageSpec, docs, resolveRelated) {
  var conceptId = pageSpec.concept;
  if (!conceptId) throw new TypeError("generateConceptPage: pageSpec.concept required");
  var concept = null;
  Object.keys(docs).some(function (file) {
    return docs[file].concepts.some(function (c) {
      if (c.tags && c.tags.concept === conceptId) {
        concept = c;
        return true;
      }
      return false;
    });
  });
  if (!concept) {
    return {
      slug:  pageSpec.slug,
      title: pageSpec.title || conceptId,
      body:  "<h1>" + (pageSpec.title || conceptId) + "</h1>" +
             '<aside class="callout callout-warning">' +
             '<p class="callout-title">Concept not found</p>' +
             "<p>No <code>@concept " + conceptId + "</code> block found anywhere under lib/. " +
             "Add the block to the source file that owns this topic and re-run the seeder.</p>" +
             "</aside>",
      generated: true,
    };
  }
  var tags = concept.tags || {};
  var title = pageSpec.title || tags.title || conceptId;
  var lines = [];
  lines.push('<h1>' + title + '</h1>');
  if (concept.prose) lines.push(_proseToHtml(concept.prose));
  if (Array.isArray(tags.sections)) {
    tags.sections.forEach(function (s) {
      var anchor = String(s.heading)
        .replace(/[^a-zA-Z0-9_]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .toLowerCase();
      lines.push('<h2 id="' + anchor + '">' + s.heading + ' <a class="anchor" href="#' + anchor + '">#</a></h2>');
      lines.push(_proseToHtml(s.body));
    });
  }
  if (tags.related) {
    var related = String(tags.related).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    var links = related.map(function (sig) {
      var href = null;
      if (typeof resolveRelated === "function") {
        try { href = resolveRelated(sig); } catch (_e) { href = null; }
      }
      if (!href) {
        var fallbackSlug = sig.replace(/^\s*b\./, "").replace(/\([^)]*\)/g, "").replace(/[^a-zA-Z0-9_]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase();
        href = "/api#" + fallbackSlug;
      }
      return '<a href="' + href + '"><code>' + sig + '</code></a>';
    });
    lines.push(
      '<aside class="callout callout-since">' +
      '<p class="callout-title">Related primitives</p>' +
      '<p>' + links.join(" · ") + '</p>' +
      '</aside>'
    );
  }
  return {
    slug:      pageSpec.slug,
    title:     title,
    body:      lines.join("\n"),
    generated: true,
  };
}

// Build a generated REFERENCE page from a harvester module.
//
// pageSpec: {
//   slug:    "reference-errors",
//   harvest: "errors",   // resolves to ./harvest-errors.js
// }
//
// The harvester module exports `harvest()` (returns the data manifest)
// and `render(manifest)` (returns the HTML body). Errors during harvest
// don't crash the seeder — the page renders a callout noting the
// failure so the operator sees the gap immediately.
function generateHarvestPage(pageSpec) {
  if (!pageSpec.harvest) throw new TypeError("generateHarvestPage: pageSpec.harvest required");
  var harvesterPath = "./harvest-" + pageSpec.harvest;
  var harvester;
  try { harvester = require(harvesterPath); }
  catch (e) {
    return {
      slug:  pageSpec.slug,
      title: pageSpec.title || pageSpec.harvest,
      body:  "<h1>" + (pageSpec.title || pageSpec.harvest) + "</h1>" +
             '<aside class="callout callout-warning">' +
             '<p class="callout-title">Harvester not found</p>' +
             "<p>Module <code>examples/wiki/lib/harvest-" + pageSpec.harvest +
             ".js</code> is missing or fails to load: " + (e && e.message || e) +
             "</p></aside>",
      generated: true,
    };
  }
  var body;
  try {
    var manifest = harvester.harvest();
    body = harvester.render(manifest);
  } catch (e) {
    body = "<h1>" + (pageSpec.title || pageSpec.harvest) + "</h1>" +
           '<aside class="callout callout-warning">' +
           '<p class="callout-title">Harvester failed</p>' +
           "<p>" + (e && e.message || e) + "</p></aside>";
  }
  // The harvester returns a body that may or may not start with <h1>.
  // Rather than second-guess, prepend a minimal <h1> only when the
  // harvester's body is missing one — keeps the harvester's own
  // styling intact when it ships its own header.
  if (body.indexOf("<h1") === -1) {
    body = "<h1>" + (pageSpec.title || pageSpec.harvest) + "</h1>\n" + body;
  }
  return {
    slug:      pageSpec.slug,
    title:     pageSpec.title || pageSpec.harvest,
    body:      body,
    generated: true,
  };
}

// Generate all pages in a curation manifest. Dispatches on page kind:
//   { namespaces: [...] } -> generatePage (primitive sections)
//   { concept: "..." }    -> generateConceptPage (narrative)
//   { harvest: "..." }    -> generateHarvestPage (reference table)
function generateAll(curation, libDir) {
  var docs = parser.parseTree(libDir);
  // Build the sig→href resolver ONCE per generation pass — every
  // primitive section's Related footer + every concept page's
  // Related primitives footer routes through this resolver to jump
  // straight to the cross-referenced primitive's page+anchor.
  var resolveRelated = _buildSignatureResolver(curation, docs);
  var pages = [];
  for (var i = 0; i < curation.pages.length; i++) {
    var spec = curation.pages[i];
    if (spec.concept) {
      pages.push(generateConceptPage(spec, docs, resolveRelated));
    } else if (spec.harvest) {
      pages.push(generateHarvestPage(spec));
    } else {
      pages.push(generatePage(spec, docs, resolveRelated));
    }
  }
  return pages;
}

module.exports = {
  generatePage:        generatePage,
  generateConceptPage: generateConceptPage,
  generateAll:         generateAll,
};
