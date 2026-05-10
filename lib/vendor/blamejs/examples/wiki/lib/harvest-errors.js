"use strict";
// harvest-errors — build-time scan of lib/ for every framework error
// class registered via b.frameworkError.defineClass(name, opts) and
// the call sites that construct each one.
//
// Two passes per file under lib/ + one level of subdirs:
//
//   1. defineClass pass — regex matches
//        var XxxError = defineClass("XxxError", { ... });
//      capturing the class name, the opts-flag set
//      (alwaysPermanent / withStatusCode / withCause), and the leading
//      line-comment block immediately above the var line.
//
//   2. Construction pass — regex matches
//        new XxxError("namespace/code", "...", ...)
//      collecting up to N distinct code strings per class, plus the
//      derived namespace prefix (the part before the first slash).
//
// Returns { classes: [...], generatedAt } sorted by class name.
//
// render(manifest) produces an HTML body suitable for direct injection
// as a wiki page body. Re-uses the wiki's existing .callout /
// .callout-title classes; introduces no new CSS.

var fs   = require("node:fs");
var path = require("node:path");

var DEFINE_CLASS_RE = /defineClass\(\s*"([A-Za-z][A-Za-z0-9_]*)"\s*(?:,\s*\{([^}]*)\})?\s*\)/g;

var COMMENT_PREFIX_RE = /^\/\/\s?/;

function _constructionRe(className) {
  // allow:dynamic-regex — className is harvested from defineClass calls in framework lib/ (controlled source), shape `[A-Za-z][A-Za-z0-9_]*`
  return new RegExp("new\\s+" + className + "\\(\\s*[\"']([^\"']+)[\"']", "g");
}

function _readSafe(file) {
  try { return fs.readFileSync(file, "utf8"); }
  catch (_) { return null; }
}

function _listFilesUnderLib(libDir) {
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

function _parseOpts(optsBody) {
  var flags = {
    alwaysPermanent: false,
    withStatusCode:  false,
    withCause:       false,
  };
  if (!optsBody) return flags;
  if (/alwaysPermanent\s*:\s*true/.test(optsBody)) flags.alwaysPermanent = true;
  if (/withStatusCode\s*:\s*true/.test(optsBody))  flags.withStatusCode  = true;
  if (/withCause\s*:\s*true/.test(optsBody))       flags.withCause       = true;
  return flags;
}

function _categoryOf(name) {
  if (/^Guard/.test(name))                          return "Guard";
  if (/^Audit/.test(name))                          return "Audit";
  if (/^Cluster/.test(name))                        return "Cluster";
  if (/^Mail|^Smtp|^Sse/.test(name))                return "Transport";
  if (/^Hpke|^TlsExporter|^HttpSig|^Acme/.test(name)) return "Crypto";
  if (/^Auth|^Session|^ApiKey|^Permissions|^Lockout/.test(name)) return "Auth";
  if (/^Db|^ExternalDb|^LocalDbThin|^Storage|^ObjectStore|^Redis/.test(name)) return "Storage";
  if (/^Cache|^Queue|^Jobs|^Scheduler|^Webhook|^LogStream/.test(name)) return "Async";
  if (/^GraphqlFederation|^A2a|^Mcp|^AiInput|^Dlp/.test(name)) return "Protocol";
  if (/^LegalHold|^WormViolation|^DdlChangeControl|^Fda21Cfr11|^Compliance|^Dora/.test(name)) return "Compliance";
  if (/^FileUpload|^StaticServe|^GateContract/.test(name)) return "HttpSurface";
  if (/^Router|^HttpClient|^Daemon|^Watcher|^Keychain|^WorkerPool|^ArgParser|^SelfUpdate|^Sandbox|^I18n|^Notify|^Testing|^Slug|^Seeder|^Handler|^Framework/.test(name)) return "Framework";
  return "Operational";
}

function _scanFile(file, libRoot, classes) {
  var src = _readSafe(file);
  if (src === null) return;
  var rel = path.relative(libRoot, file).replace(/\\/g, "/");
  DEFINE_CLASS_RE.lastIndex = 0;
  var m;
  while ((m = DEFINE_CLASS_RE.exec(src)) !== null) {
    var name = m[1];
    var flags = _parseOpts(m[2]);
    var prose = _proseAbove(src, m.index);
    classes.push({
      name:    name,
      file:    rel,
      flags:   flags,
      prose:   prose,
      codes:   [],
      namespaces: [],
      messageShape: flags.withCause ? "(code, message, cause)"
                  : flags.alwaysPermanent ? "(code, message)"
                  : flags.withStatusCode ? "(code, message, permanent, statusCode)"
                  : "(code, message, permanent)",
    });
  }
}

function _collectConstructionCodes(files, classes) {
  for (var f = 0; f < files.length; f++) {
    var src = _readSafe(files[f]);
    if (src === null) continue;
    for (var k = 0; k < classes.length; k++) {
      var c = classes[k];
      var re = _constructionRe(c.name);
      var m;
      while ((m = re.exec(src)) !== null) {
        var code = m[1];
        if (c.codes.indexOf(code) === -1) c.codes.push(code);
        var slash = code.indexOf("/");
        var ns = slash > 0 ? code.substring(0, slash) : code;
        if (c.namespaces.indexOf(ns) === -1) c.namespaces.push(ns);
      }
    }
  }
  for (var x = 0; x < classes.length; x++) {
    classes[x].codes.sort();
    classes[x].namespaces.sort();
  }
}

function harvest(opts) {
  opts = opts || {};
  var libRoot = opts.libRoot || path.resolve(__dirname, "..", "..", "..", "lib");
  var files   = _listFilesUnderLib(libRoot);
  var classes = [];

  for (var i = 0; i < files.length; i++) {
    _scanFile(files[i], libRoot, classes);
  }

  _collectConstructionCodes(files, classes);

  classes.sort(function (a, b) {
    if (a.name < b.name) return -1;
    if (a.name > b.name) return 1;
    return 0;
  });

  return {
    generatedAt: new Date().toISOString(),
    classes:     classes,
  };
}

function _esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function _flagPills(flags) {
  var parts = [];
  if (flags.alwaysPermanent) parts.push("alwaysPermanent");
  if (flags.withStatusCode)  parts.push("withStatusCode");
  if (flags.withCause)       parts.push("withCause");
  if (parts.length === 0)    parts.push("default");
  return parts.map(function (p) { return "<code>" + _esc(p) + "</code>"; }).join(" ");
}

function _groupByCategory(classes) {
  var groups = {};
  for (var i = 0; i < classes.length; i++) {
    var cat = _categoryOf(classes[i].name);
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(classes[i]);
  }
  return groups;
}

function render(manifest) {
  if (!manifest || !Array.isArray(manifest.classes)) {
    throw new TypeError("render: manifest.classes array required");
  }
  var out = [];
  out.push('<h1>Error catalog</h1>');
  out.push('<p>Every operational error class registered via ' +
    '<code>b.frameworkError.defineClass</code>. Each class extends ' +
    '<code>FrameworkError</code> and exposes a stable shape: ' +
    '<code>{ name, code, message, isFrameworkError: true }</code>. ' +
    'Catch with <code>err instanceof b.FrameworkError</code> for the ' +
    'unified branch, or check <code>err.name</code> / the per-class ' +
    '<code>isXxxError</code> flag for fine-grained handling.</p>');

  out.push('<div class="callout"><div class="callout-title">Stable contract</div>' +
    '<p>The class name and the per-namespace <code>code</code> prefix ' +
    'are stable across patch releases. Code suffixes after the ' +
    'first <code>/</code> are documented per primitive — operators ' +
    'matching on full codes should pin to a minor version.</p></div>');

  out.push('<p>Total classes harvested: <strong>' +
    manifest.classes.length + '</strong>. Generated ' +
    _esc(manifest.generatedAt) + '.</p>');

  var groups = _groupByCategory(manifest.classes);
  var categories = Object.keys(groups).sort(); // allow:bare-canonicalize-walk — wiki harvester rendering deterministic display order, not canonicalising for crypto/audit
  for (var g = 0; g < categories.length; g++) {
    var cat = categories[g];
    var rows = groups[cat];
    var catSlug = String(cat).toLowerCase().replace(/[^a-z0-9_]+/g, "-").replace(/^-+|-+$/g, "");
    out.push('<h2 id="cat-' + catSlug + '">' + _esc(cat) + ' <a class="anchor" href="#cat-' + catSlug + '">#</a></h2>');
    out.push('<table>');
    out.push('<thead><tr><th>Class</th><th>Constructor</th><th>Flags</th><th>Code namespaces</th><th>Description</th></tr></thead>');
    out.push('<tbody>');
    for (var r = 0; r < rows.length; r++) {
      var c = rows[r];
      var nsCell = c.namespaces.length === 0
        ? '<em>none harvested</em>'
        : c.namespaces.map(function (n) { return '<code>' + _esc(n) + '/*</code>'; }).join(', ');
      var prose = c.prose
        ? _esc(c.prose)
        : '<em>(no prose comment in source)</em>';
      out.push('<tr>' +
        '<td><code>' + _esc(c.name) + '</code><br><small>' + _esc(c.file) + '</small></td>' +
        '<td><code>' + _esc(c.messageShape) + '</code></td>' +
        '<td>' + _flagPills(c.flags) + '</td>' +
        '<td>' + nsCell + '</td>' +
        '<td>' + prose + '</td>' +
      '</tr>');
    }
    out.push('</tbody></table>');
  }

  out.push('<div class="callout"><div class="callout-title">Dynamic codes</div>' +
    '<p>Construction sites that pass a non-literal first argument ' +
    '(template strings, variables) are intentionally not harvested ' +
    '— the catalog only records statically-resolvable code namespaces. ' +
    'Per-primitive wiki pages document the full code surface.</p></div>');

  return out.join("\n");
}

module.exports = {
  harvest:        harvest,
  render:         render,
  _proseAbove:    _proseAbove,
  _parseOpts:     _parseOpts,
  _categoryOf:    _categoryOf,
};
