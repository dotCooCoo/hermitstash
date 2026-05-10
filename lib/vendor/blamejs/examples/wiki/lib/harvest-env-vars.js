"use strict";
// harvest-env-vars — build-time scan of lib/ + the wiki example app
// for every operator-facing environment variable read at runtime.
//
// Two read shapes count as canonical:
//
//   safeEnv.readVar("NAME", { type: "...", default: ..., required: ... })
//     The framework's typed-env reader. The opts object — when present
//     as a static literal — is preserved verbatim so the wiki page can
//     show the schema (type / default / required / enum / maxBytes /
//     strip).
//
//   process.env.NAME
//     Direct reads. Mostly dev-tooling and the wiki example app's own
//     boot path; harvested separately so the rendered page can flag
//     them as "less canonical" surface.
//
// Scope walked:
//   - lib/*.js                     (every framework module)
//   - lib/<subdir>/*.js            (one level — vault/, parsers/, …)
//   - examples/wiki/lib/build-app.js
//   - examples/wiki/server.js
//
// Returns { vars: [...], generatedAt } sorted by var name. Each entry:
//
//   {
//     name:      "BLAMEJS_NTP_SERVERS",
//     category:  "core" | "security" | "wiki",
//     files:     [{ file, line, shape: "readVar"|"process.env" }, ...],
//     schemas:   [ "{ default: \"\" }", ... ]   // unique opts texts
//     prose:     "..."   // leading comment block above the first read
//   }
//
// render(manifest) emits an HTML body suitable for direct injection as
// a wiki page. Three tables — Core / Security / Wiki example — with
// columns: Name | Default | Effect | Where read.

var fs   = require("node:fs");
var path = require("node:path");

// readVar matcher — captures the var name (group 1) and, when an opts
// literal follows, the brace-bounded body (group 2). Non-greedy on the
// opts body, but we only match a single-level object literal so a
// nested `{` will simply not capture (the schema will appear as raw
// readVar without opts, which is the right fallback shape).
var READVAR_RE   = /safeEnv\.readVar\(\s*["']([A-Z_][A-Z0-9_]*)["']\s*(?:,\s*(\{[^{}]*\}))?\s*\)/g;
var PROCENV_RE   = /process\.env\.([A-Z_][A-Z0-9_]*)/g;

var COMMENT_PREFIX_RE = /^\/\/\s?/;

function _readSafe(file) {
  try { return fs.readFileSync(file, "utf8"); }
  catch (_) { return null; }
}

// Replace every `// …` line comment and `/* … */` block comment with
// equal-length spaces (preserving newlines + byte offsets) so the
// readVar / process.env regex passes don't capture documentation
// references like "process.env.BLAMEJS_*". String literals are
// preserved — operators sometimes embed env-var names in strings
// (logs, error messages) and those are still real surface to harvest.
function _maskComments(src) {
  var out = src.split("");
  var i = 0;
  var n = out.length;
  var inSingle = false, inDouble = false, inTpl = false, inEsc = false;
  while (i < n) {
    var ch = out[i];
    if (inEsc) { inEsc = false; i++; continue; }
    if (inSingle) {
      if (ch === "\\") { inEsc = true; i++; continue; }
      if (ch === "'") inSingle = false;
      i++; continue;
    }
    if (inDouble) {
      if (ch === "\\") { inEsc = true; i++; continue; }
      if (ch === "\"") inDouble = false;
      i++; continue;
    }
    if (inTpl) {
      if (ch === "\\") { inEsc = true; i++; continue; }
      if (ch === "`") inTpl = false;
      i++; continue;
    }
    if (ch === "'") { inSingle = true; i++; continue; }
    if (ch === "\"") { inDouble = true; i++; continue; }
    if (ch === "`") { inTpl = true; i++; continue; }
    if (ch === "/" && i + 1 < n && out[i + 1] === "/") {
      // Line comment — blank to end-of-line.
      while (i < n && out[i] !== "\n") { out[i] = " "; i++; }
      continue;
    }
    if (ch === "/" && i + 1 < n && out[i + 1] === "*") {
      out[i] = " "; out[i + 1] = " "; i += 2;
      while (i < n) {
        if (out[i] === "*" && i + 1 < n && out[i + 1] === "/") {
          out[i] = " "; out[i + 1] = " "; i += 2;
          break;
        }
        if (out[i] !== "\n") out[i] = " ";
        i++;
      }
      continue;
    }
    i++;
  }
  return out.join("");
}

function _listLibFiles(libDir) {
  var out = [];
  var entries;
  try { entries = fs.readdirSync(libDir, { withFileTypes: true }); }
  catch (_) { return out; }
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var full = path.join(libDir, e.name);
    if (e.isFile() && e.name.endsWith(".js")) {
      out.push(full);
    } else if (e.isDirectory() && e.name !== "vendor" && e.name !== "node_modules") {
      var sub;
      try { sub = fs.readdirSync(full, { withFileTypes: true }); }
      catch (_) { sub = []; }
      for (var j = 0; j < sub.length; j++) {
        if (sub[j].isFile() && sub[j].name.endsWith(".js")) {
          out.push(path.join(full, sub[j].name));
        }
      }
    }
  }
  return out;
}

function _lineNumberOf(source, idx) {
  var n = 1;
  for (var i = 0; i < idx && i < source.length; i++) {
    if (source.charCodeAt(i) === 10 /* \n */) n++;
  }
  return n;
}

// Walk upward from `matchIndex`, collecting contiguous `// …` lines
// that immediately precede the read site. Empty lines and code lines
// terminate the block.
function _proseAbove(source, matchIndex) {
  var lineStart = source.lastIndexOf("\n", matchIndex - 1) + 1;
  if (lineStart <= 0) return "";
  var lines = [];
  var cursor = lineStart - 1;
  while (cursor > 0) {
    var prevStart = source.lastIndexOf("\n", cursor - 1) + 1;
    var line = source.substring(prevStart, cursor);
    var trimmed = line.replace(/^\s+|\s+$/g, "");
    if (trimmed.indexOf("//") === 0) {
      lines.unshift(trimmed.replace(COMMENT_PREFIX_RE, ""));
      cursor = prevStart - 1;
      if (prevStart === 0) break;
    } else {
      break;
    }
  }
  return lines.join(" ").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "");
}

function _categoryOf(name) {
  if (/^WIKI_/.test(name))                       return "wiki";
  if (/_PASSPHRASE$/.test(name))                 return "security";
  if (/^BLAMEJS_AUDIT_SIGNING_/.test(name))      return "security";
  if (/^BLAMEJS_VAULT_/.test(name))              return "security";
  if (/^BLAMEJS_BACKUP_/.test(name))             return "security";
  if (/^BLAMEJS_/.test(name))                    return "core";
  // Bare conventions surface but stay separate from BLAMEJS_*; treat
  // them as core operator-facing knobs.
  if (name === "NODE_ENV" || name === "PORT" ||
      name === "HOSTNAME" || name === "LOG_LEVEL") return "core";
  return "core";
}

function _normalizeSchemaText(s) {
  return String(s)
    .replace(/\s+/g, " ")
    .replace(/^\s+|\s+$/g, "");
}

function _scanFile(file, repoRoot, byName) {
  var src = _readSafe(file);
  if (src === null) return;
  var rel = path.relative(repoRoot, file).replace(/\\/g, "/");
  // Mask comments before regex scanning so `// process.env.X` in
  // doc-comments doesn't pollute the catalog. Offsets are preserved
  // so line numbers + prose lookup against the ORIGINAL source still
  // work. Prose lookup walks backward through the original source so
  // leading `//` blocks remain visible.
  var scan = _maskComments(src);

  READVAR_RE.lastIndex = 0;
  var m;
  while ((m = READVAR_RE.exec(scan)) !== null) {
    var name = m[1];
    var schema = m[2] ? _normalizeSchemaText(m[2]) : null;
    var line = _lineNumberOf(src, m.index);
    var prose = _proseAbove(src, m.index);
    _record(byName, name, rel, line, "readVar", schema, prose);
  }

  PROCENV_RE.lastIndex = 0;
  while ((m = PROCENV_RE.exec(scan)) !== null) {
    var procName = m[1];
    var procLine = _lineNumberOf(src, m.index);
    var procProse = _proseAbove(src, m.index);
    _record(byName, procName, rel, procLine, "process.env", null, procProse);
  }
}

function _record(byName, name, file, line, shape, schema, prose) {
  var entry = byName[name];
  if (!entry) {
    entry = byName[name] = {
      name:     name,
      category: _categoryOf(name),
      files:    [],
      schemas:  [],
      prose:    "",
    };
  }
  // Dedupe by file+line so a single source position isn't double-counted
  // when both regexes happen to overlap (they shouldn't, but cheap).
  for (var i = 0; i < entry.files.length; i++) {
    if (entry.files[i].file === file && entry.files[i].line === line) return;
  }
  entry.files.push({ file: file, line: line, shape: shape });
  if (schema && entry.schemas.indexOf(schema) === -1) {
    entry.schemas.push(schema);
  }
  // Keep the first non-empty prose block we encounter — the others tend
  // to be local "default to X" comments rather than the var's contract.
  if (!entry.prose && prose) entry.prose = prose;
}

function harvest(opts) {
  opts = opts || {};
  var repoRoot = opts.repoRoot || path.resolve(__dirname, "..", "..", "..");
  var libRoot  = opts.libRoot  || path.join(repoRoot, "lib");

  var files = _listLibFiles(libRoot);

  var wikiServer  = path.join(repoRoot, "examples", "wiki", "server.js");
  var wikiBuildApp = path.join(repoRoot, "examples", "wiki", "lib", "build-app.js");
  if (fs.existsSync(wikiServer))   files.push(wikiServer);
  if (fs.existsSync(wikiBuildApp)) files.push(wikiBuildApp);

  var byName = Object.create(null);
  for (var i = 0; i < files.length; i++) {
    _scanFile(files[i], repoRoot, byName);
  }

  var vars = Object.keys(byName)
    .sort()
    .map(function (k) { return byName[k]; });

  // Stable ordering of the per-var file list — primary by file path,
  // secondary by line number — so consecutive harvests produce a
  // byte-identical manifest.
  for (var v = 0; v < vars.length; v++) {
    vars[v].files.sort(function (a, b) {
      if (a.file < b.file) return -1;
      if (a.file > b.file) return 1;
      return a.line - b.line;
    });
    vars[v].schemas.sort();
  }

  return {
    generatedAt: new Date().toISOString(),
    vars:        vars,
  };
}

function _esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Pull a `default:` field out of a schema literal (best effort — only
// resolves static literal defaults). Returns the rendered HTML cell or
// "—" when no default is detectable. Multiple schemas across call sites
// surface together so operator can spot drift between sites.
function _defaultCell(schemas) {
  if (!schemas || schemas.length === 0) return "&mdash;";
  var defaults = [];
  for (var i = 0; i < schemas.length; i++) {
    var s = schemas[i];
    var m = /default\s*:\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|true|false|null|-?\d+(?:\.\d+)?)/.exec(s);
    if (m) {
      if (defaults.indexOf(m[1]) === -1) defaults.push(m[1]);
    }
  }
  if (defaults.length === 0) return "&mdash;";
  return defaults.map(function (d) { return "<code>" + _esc(d) + "</code>"; }).join(" / ");
}

function _typeCell(schemas) {
  if (!schemas || schemas.length === 0) return "string";
  var types = [];
  for (var i = 0; i < schemas.length; i++) {
    var m = /type\s*:\s*["']([a-z]+)["']/.exec(schemas[i]);
    if (m && types.indexOf(m[1]) === -1) types.push(m[1]);
  }
  if (types.length === 0) return "string";
  return types.join(" / ");
}

function _whereCell(files) {
  if (!files || files.length === 0) return "&mdash;";
  return files.map(function (f) {
    return '<code>' + _esc(f.file) + ':' + f.line + '</code>';
  }).join("<br>");
}

function _proseCell(entry) {
  if (entry.prose) return _esc(entry.prose);
  if (entry.schemas.length > 0) {
    return '<small>schema: <code>' + _esc(entry.schemas[0]) + '</code></small>';
  }
  return '<em>(no prose; consult source)</em>';
}

function _categoryTitle(cat) {
  if (cat === "core")     return "Core framework (BLAMEJS_*)";
  if (cat === "security") return "Security & secrets";
  if (cat === "wiki")     return "Wiki example app (WIKI_*)";
  return cat;
}

function _categoryIntro(cat) {
  if (cat === "core") {
    return "Operator knobs read by the framework's lib/ modules during " +
           "boot and on first use. All optional unless marked required " +
           "in the schema column.";
  }
  if (cat === "security") {
    return "Passphrases and signing-mode selectors. The framework reads " +
           "these once at vault / audit init and then strips them from " +
           "<code>process.env</code>. Set them via the operator's secret " +
           "manager — never bake into a Dockerfile or shell history.";
  }
  if (cat === "wiki") {
    return "Knobs read only by <code>examples/wiki</code> — the operator's " +
           "downstream app reads its own equivalents and these will not " +
           "appear in framework deployments.";
  }
  return "";
}

function render(manifest) {
  if (!manifest || !Array.isArray(manifest.vars)) {
    throw new TypeError("render: manifest.vars array required");
  }

  var groups = { core: [], security: [], wiki: [] };
  for (var i = 0; i < manifest.vars.length; i++) {
    var v = manifest.vars[i];
    var bucket = groups[v.category] || groups.core;
    bucket.push(v);
  }

  var out = [];
  out.push('<h1>Environment variables</h1>');
  out.push('<p>Every environment variable the framework reads at runtime, ' +
    'harvested directly from <code>lib/</code> and the example app. The ' +
    'canonical reader is <code>b.safeEnv.readVar(name, schema)</code> — ' +
    'it coerces the raw string into the declared type, applies the ' +
    'declared default when unset, and (for secrets) strips the value ' +
    'from <code>process.env</code> after the first read so a later ' +
    '<code>process.env</code> dump cannot leak it.</p>');

  out.push('<p>Total variables harvested: <strong>' +
    manifest.vars.length + '</strong> across ' +
    Object.keys(groups).filter(function (k) { return groups[k].length > 0; }).length +
    ' categories. Generated ' + _esc(manifest.generatedAt) + '.</p>');

  var order = ["core", "security", "wiki"];
  for (var g = 0; g < order.length; g++) {
    var cat  = order[g];
    var rows = groups[cat];
    if (!rows || rows.length === 0) continue;

    var catSlug = String(cat).toLowerCase().replace(/[^a-z0-9_]+/g, "-").replace(/^-+|-+$/g, "");
    out.push('<h2 id="cat-' + catSlug + '">' + _esc(_categoryTitle(cat)) + ' <a class="anchor" href="#cat-' + catSlug + '">#</a></h2>');
    out.push('<p>' + _categoryIntro(cat) + '</p>');
    out.push('<table>');
    out.push('<thead><tr>' +
      '<th>Name</th>' +
      '<th>Type</th>' +
      '<th>Default</th>' +
      '<th>Effect</th>' +
      '<th>Where read</th>' +
      '</tr></thead>');
    out.push('<tbody>');

    for (var r = 0; r < rows.length; r++) {
      var entry = rows[r];
      out.push('<tr>' +
        '<td><code>' + _esc(entry.name) + '</code></td>' +
        '<td>' + _esc(_typeCell(entry.schemas)) + '</td>' +
        '<td>' + _defaultCell(entry.schemas) + '</td>' +
        '<td>' + _proseCell(entry) + '</td>' +
        '<td>' + _whereCell(entry.files) + '</td>' +
      '</tr>');
    }

    out.push('</tbody></table>');
  }

  out.push('<div class="callout"><div class="callout-title">Computed names</div>' +
    '<p>Variables read via a computed key — <code>process.env[someVar]</code> ' +
    'or <code>safeEnv.readVar(prefix + suffix)</code> — are intentionally ' +
    'not harvested. The catalog only records statically-resolvable names. ' +
    'Operators relying on runtime-computed env keys should document them ' +
    'in their own deploy manifest.</p></div>');

  return out.join("\n");
}

module.exports = {
  harvest:           harvest,
  render:            render,
  _proseAbove:       _proseAbove,
  _categoryOf:       _categoryOf,
  _lineNumberOf:     _lineNumberOf,
  _normalizeSchemaText: _normalizeSchemaText,
};
