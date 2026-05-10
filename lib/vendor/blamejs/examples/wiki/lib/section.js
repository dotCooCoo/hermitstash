"use strict";
// section() — wiki primitive-section helper.
//
// Replaces the hand-rolled four-piece HTML pattern (heading + opts
// block + prose + example) that every wiki primitive section ships.
// Pages become a list of section({...}) calls instead of raw HTML
// strings. The helper emits validator-compliant HTML so the existing
// gate (test/validate-primitive-sections.js) keeps working unchanged.
//
// Shape:
//
//   section({
//     signature:  "b.auth.password.hash(plain, opts)",
//     prose:      "<p>Argon2id password hashing…</p>",
//     example:    "auth/password-hash.example.js",   // path under snippets/
//                                                    // OR raw string code
//     opts:       "auto",        // probe lib for allowed keys, OR
//                 { key: "type" } // inline object of name → type-comment
//                                 // OR an HTML string already shaped
//     since:      "0.7.19",
//     status:     "stable",       // stable | experimental | deprecated
//     compliance: ["hipaa", "pci-dss", "gdpr"],
//     related:    ["b.session", "b.middleware.bearerAuth"],
//     anchor:     "auth-password-hash",  // optional override; default
//                                        // derives from signature
//     headingTag: "h3",           // h2|h3 (default h3)
//   })
//
// Returns an HTML string the page seeder splits on the body line array.
//
// Auto-injection:
//   • opts: "auto" — calls lib/opts-resolver.js to harvest the allowed
//     keys at seed time. When the probe fails (positional-args, async
//     validateOpts, etc.) the helper falls back to a "// see lib for
//     opts shape" placeholder + a console warning so the wiki author
//     knows to hand-author the block.
//   • example: "<path>" — reads examples/wiki/snippets/<path> and
//     embeds it. INTEGRATION_FIXTURES from b.guard* modules can be
//     passed inline by the page seeder when the snippet lives in the
//     framework instead of the wiki tree.

var fs = require("node:fs");
var path = require("node:path");
var optsResolver = require("./opts-resolver");

var SNIPPETS_DIR = path.join(__dirname, "..", "snippets");

// ---- HTML escape (text-only contexts: titles, plain prose attrs) ----
function _esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Anchor slug from signature: strip wrapping <code>, b. prefix, opts,
// non-word chars; lowercase.
function _slugFromSignature(signature) {
  return String(signature)
    .replace(/<\/?code>/g, "")
    .replace(/^\s*b\./, "")
    .replace(/\([^)]*\)/g, "")
    .replace(/\s+\/\s+/g, "-")
    .replace(/[^a-zA-Z0-9_]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase();
}

// Render the meta header (status / since / compliance pills).
function _renderMeta(opts) {
  var pills = [];
  if (opts.status && opts.status !== "stable") {
    pills.push('<span class="pill pill-' + _esc(opts.status) + '">' + _esc(opts.status) + '</span>');
  } else if (opts.status === "stable") {
    // Render stable explicitly only when the author asked — most
    // sections don't need a "stable" badge cluttering the header.
    pills.push('<span class="pill pill-stable">stable</span>');
  }
  if (opts.since) {
    pills.push('<span class="pill pill-since">' + _esc(opts.since) + '</span>');
  }
  if (Array.isArray(opts.compliance)) {
    for (var i = 0; i < opts.compliance.length; i++) {
      var p = String(opts.compliance[i]).toLowerCase();
      pills.push('<span class="pill pill-compliance pill-' + _esc(p) + '">' + _esc(p) + '</span>');
    }
  }
  if (pills.length === 0) return "";
  return '<header class="prim-meta">' + pills.join("") + '</header>';
}

// Render the related-primitives footer.
//
// `resolve` (optional) is a sig → href resolver supplied by the
// page-generator. When set, related references jump straight to the
// rendered page+anchor of each cross-referenced primitive. When unset
// (or when the resolver returns a falsy value), the link falls back
// to the /api catch-all.
function _renderRelated(related, resolve) {
  if (!Array.isArray(related) || related.length === 0) return "";
  var links = related.map(function (sig) {
    var href = null;
    if (typeof resolve === "function") {
      try { href = resolve(sig); } catch (_e) { href = null; }
    }
    if (!href) href = "/api#" + _slugFromSignature(sig);
    return '<a href="' + href + '"><code>' + _esc(sig) + '</code></a>';
  });
  return (
    '<aside class="callout callout-since">' +
    '<p class="callout-title">Related</p>' +
    '<p>' + links.join(" · ") + '</p>' +
    '</aside>'
  );
}

// Resolve opts to the HTML for the opts code block.
//
//   "auto"         → probe lib, build typed-object form
//   { key: "..." } → inline mapping
//   "<pre>...</pre>" → raw HTML, used as-is
//   string         → wrap as a single js code block
function _renderOpts(signature, opts) {
  if (opts === undefined || opts === null || opts === false) return "";
  if (opts === "auto") {
    var probe = optsResolver.resolve(signature);
    if (!probe.ok) {
      // Probe failed — most commonly because the function takes
      // optional opts (`opts?`) and doesn't sync-validate. Emit
      // nothing rather than an ugly placeholder; the author can
      // declare opts manually via @opts when the probe can't reach
      // the truth. The validator (Phase 5) flags missing opts blocks
      // for required-opts signatures so this can't silently hide a
      // primitive whose opts ARE required.
       
      console.warn("[section] opts:auto failed for", signature, "—", probe.reason); // allow:console-direct — wiki seeder helper, runs at boot before b.log is wired
      return "";
    }
    var lines = probe.allowList.map(function (k) {
      return "  " + k + ":";
    }).join(",\n");
    return (
      '<pre><code class="language-javascript">{\n' +
      lines + ",\n" +
      "}</code></pre>"
    );
  }
  if (typeof opts === "string") {
    var trimmed = opts.replace(/^\s+|\s+$/g, "");
    if (trimmed.indexOf("<pre") === 0) return trimmed;
    return '<pre><code class="language-javascript">' + opts + "</code></pre>";
  }
  if (typeof opts === "object") {
    var keys = Object.keys(opts);
    var rendered = keys.map(function (k) {
      var typeStr = String(opts[k]);
      return "  " + k + ": " + typeStr + ",";
    }).join("\n");
    return (
      '<pre><code class="language-javascript">{\n' +
      rendered +
      "\n}</code></pre>"
    );
  }
  return "";
}

// Resolve example to HTML. Path under snippets/ → readFile + render.
// Raw string → render as the body of a code block.
function _renderExample(example, lang) {
  if (!example) return "";
  var language = lang || "javascript";
  if (typeof example === "string") {
    var maybePath = example.indexOf("\n") === -1 && example.indexOf(" ") === -1 && /\.[a-z0-9]+$/.test(example);
    if (maybePath) {
      var abs = path.join(SNIPPETS_DIR, example);
      try {
        var body = fs.readFileSync(abs, "utf8");
        // Snippets keep their "use strict" / shebangs visible — that's
        // useful when learning. No transformation.
        return '<pre><code class="language-' + _esc(language) + '">' + _esc(body) + "</code></pre>";
      } catch (_e) {

        console.warn("[section] example snippet not found:", abs); // allow:console-direct — wiki seeder helper, runs at boot before b.log is wired
        return '<pre><code class="language-' + _esc(language) + '">// snippet not found: ' + _esc(example) + "</code></pre>";
      }
    }
    return '<pre><code class="language-' + _esc(language) + '">' + example + "</code></pre>";
  }
  return "";
}

function section(opts) {
  if (!opts || typeof opts !== "object") {
    throw new TypeError("section: expected opts object");
  }
  if (!opts.signature) throw new TypeError("section: opts.signature is required");
  if (!opts.prose) throw new TypeError("section: opts.prose is required");

  var headingTag = opts.headingTag || "h3";
  if (headingTag !== "h2" && headingTag !== "h3") {
    throw new TypeError("section: headingTag must be h2 or h3");
  }

  var anchor = opts.anchor || _slugFromSignature(opts.signature);
  var heading =
    "<" + headingTag + ' id="' + _esc(anchor) + '">' +
    opts.signature +
    ' <a class="anchor" href="#' + _esc(anchor) + '">#</a>' +
    "</" + headingTag + ">";

  var meta = _renderMeta(opts);

  // Prose may already be a `<p>` chain or a single string; the helper
  // accepts either. Authors writing concept-shaped sections often pass
  // multiple paragraphs separated by `\n` — preserve as-is.
  var prose = opts.prose;
  if (typeof prose !== "string") {
    throw new TypeError("section: opts.prose must be a string");
  }
  if (prose.indexOf("<p") !== 0 && prose.indexOf("<aside") !== 0) {
    prose = "<p>" + prose + "</p>";
  }

  var optsHtml = _renderOpts(opts.signature, opts.opts);
  var exampleHtml = _renderExample(opts.example, opts.exampleLang);
  var relatedHtml = _renderRelated(opts.related, opts.resolveRelated);

  // Validator order: heading, opts (if signature has opts), prose, example.
  // Meta sits between heading and opts. Related sits at the bottom.
  var parts = [heading];
  if (meta) parts.push(meta);
  if (optsHtml) parts.push(optsHtml);
  parts.push(prose);
  if (exampleHtml) parts.push(exampleHtml);
  if (relatedHtml) parts.push(relatedHtml);
  return parts.join("\n");
}

// h2() — convenience for top-level concept dividers (Database / Auth /
// etc.). Same shape as section() but renders as <h2> and skips the
// opts/example block by default.
function h2(opts) {
  if (typeof opts === "string") opts = { title: opts };
  if (!opts.title) throw new TypeError("h2: opts.title is required");
  var anchor = opts.anchor || String(opts.title).replace(/[^a-zA-Z0-9_]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase();
  return (
    '<h2 id="' + _esc(anchor) + '">' +
    _esc(opts.title) +
    ' <a class="anchor" href="#' + _esc(anchor) + '">#</a>' +
    "</h2>"
  );
}

// callout(kind, title, body) — convenience for the styled callouts.
// kind: note | warn | tip | security | compliance | since | deprecated.
function callout(kind, title, body) {
  var classes = "callout";
  if (kind && kind !== "note") classes += " callout-" + kind;
  return (
    '<aside class="' + classes + '">' +
    '<p class="callout-title">' + _esc(title) + "</p>" +
    body +
    "</aside>"
  );
}

module.exports = {
  section: section,
  h2:      h2,
  callout: callout,
  // exposed for tests + symbol-index harvester
  _slugFromSignature: _slugFromSignature,
};
