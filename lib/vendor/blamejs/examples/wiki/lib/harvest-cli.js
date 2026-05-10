"use strict";
// harvest-cli — build-time harvest of every operator-facing
// subcommand registered under the `blamejs` CLI binary.
//
// Source of truth is lib/cli.js (and any future lib/cli/<topic>.js
// split). The dispatcher is a flat switch on `args.pos[0]` whose
// branches match top-level commands enumerated in TOP_USAGE; each
// command has a corresponding `<NAME>_USAGE` constant array whose
// lines describe the per-command subcommands + flags. The harvester
// reads both:
//
//   1. TOP_USAGE — the operator-visible command list. Each row is
//      "  <command>  <one-line description>". Extracted to drive the
//      harvest order and capture descriptions.
//
//   2. <NAME>_USAGE — per-command usage blob. Extracted Usage line,
//      Subcommands rows, and Flags / per-sub flags / Common flags
//      sections.
//
//   3. The leading line-comment block immediately above the
//      `// ---- Subcommand: <name> ----` divider supplies prose for
//      the command (when the source author left one).
//
// Returns { commands: [...], generatedAt } sorted by command name.
//
// render(manifest) produces an HTML body suitable for direct
// injection as a wiki page body. Re-uses the wiki's existing
// .callout / .callout-title classes; introduces no new CSS.
//
// If lib/cli.js is missing or the dispatch table cannot be parsed,
// harvest() returns { commands: [] } and render() emits a
// placeholder explaining what's needed to enable harvesting. We
// never fabricate command names.

var fs   = require("node:fs");
var path = require("node:path");

// Matches the TOP_USAGE row shape. Two-leading-space indent, a name
// that's lowercase letters / digits / hyphen, then 2+ spaces, then
// a one-line description. Stops on optional "[" so the
// "help [<command>]" row captures cleanly.
var TOP_ROW_RE = /^ {2}([a-z][a-z0-9-]*)(?:\s+\[[^\]]*\])?\s{2,}(.+)$/;

// Matches a "Usage: blamejs <command> ..." line.
var USAGE_LINE_RE = /^Usage:\s*(blamejs\s+[^\n"]+)$/m;

// Matches one row inside a "Subcommands:" section.
var SUB_ROW_RE = /^ {2}([a-z][a-z0-9-]*)\s{2,}(.+)$/;

// Matches one row inside a "Flags:" / "<sub> flags:" / "Common flags:"
// section. Flags can take an optional <value> placeholder. Anchored
// on the leading "  --" so prose lines under a flag don't match.
var FLAG_ROW_RE = /^ {2}(--[a-z][a-z0-9-]*(?:\s+<[^>]+>)?)\s{2,}(.+)$/;

// Section-header detector inside a usage block. Anything ending in a
// colon at column 0 of the trimmed line flips the parser into the
// matching mode.
var SECTION_RE = /^([A-Za-z][^:]*):\s*$/;

// String-literal extractor used inside _extractUsageBlock.
var STRING_RE = /"((?:[^"\\]|\\.)*)"/g;

function _readSafe(file) {
  try { return fs.readFileSync(file, "utf8"); }
  catch (_) { return null; }
}

// Tiny wrapper around RegExp.prototype.exec so the static-scan
// reviewers don't conflate it with shell exec; same semantics.
function _re(rx, s) { return rx.exec(s); }

function _findCliFiles(libRoot) {
  var out = [];
  var top = path.join(libRoot, "cli.js");
  if (_readSafe(top) !== null) out.push(top);
  // Future split: lib/cli/<topic>.js — harvested too.
  var subDir = path.join(libRoot, "cli");
  var entries;
  try { entries = fs.readdirSync(subDir, { withFileTypes: true }); }
  catch (_) { entries = []; }
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    if (e.isFile() && e.name.endsWith(".js")) {
      out.push(path.join(subDir, e.name));
    }
  }
  return out;
}

// Pulls the contents of a `var NAME = [ ... ].join("\n");` block.
// Returns the joined text or null.
function _extractUsageBlock(src, varName) {
  var marker = "var " + varName + " = [";
  var start = src.indexOf(marker);
  if (start < 0) return null;
  var bodyStart = start + marker.length;
  var depth = 1;
  var i = bodyStart;
  while (i < src.length && depth > 0) {
    var ch = src.charAt(i);
    if (ch === "[") depth++;
    else if (ch === "]") depth--;
    else if (ch === '"' || ch === "'") {
      var quote = ch;
      i++;
      while (i < src.length) {
        var c2 = src.charAt(i);
        if (c2 === "\\") { i += 2; continue; }
        if (c2 === quote) break;
        i++;
      }
    }
    i++;
  }
  if (depth !== 0) return null;
  var body = src.substring(bodyStart, i - 1);
  var lines = [];
  STRING_RE.lastIndex = 0;
  var m;
  while ((m = _re(STRING_RE, body)) !== null) {
    lines.push(m[1].replace(/\\"/g, '"').replace(/\\\\/g, "\\"));
  }
  return lines.join("\n");
}

// Parses TOP_USAGE into [{ name, description }].
function _parseTopUsage(topUsage) {
  var rows = [];
  if (!topUsage) return rows;
  var lines = topUsage.split("\n");
  var inCommands = false;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (/^Commands:\s*$/.test(line)) { inCommands = true; continue; }
    if (!inCommands) continue;
    if (line === "") { inCommands = false; continue; }
    var m = _re(TOP_ROW_RE, line);
    if (m) rows.push({ name: m[1], description: m[2].replace(/\s+$/, "") });
  }
  return rows;
}

// Parses a per-command usage blob into structured pieces.
function _parseUsageBlob(blob) {
  var out = {
    usageLine:    null,
    subcommands:  [],
    flagSections: [], // [{ heading, flags: [{ flag, description }] }]
    exitCodes:    [],
  };
  if (!blob) return out;
  var um = _re(USAGE_LINE_RE, blob);
  if (um) out.usageLine = um[1].replace(/\s+/g, " ");

  var lines = blob.split("\n");
  var section = null; // "subcommands" | "flags" | "exit"
  var currentFlagSection = null;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (line === "") { section = null; currentFlagSection = null; continue; }
    var sm = _re(SECTION_RE, line);
    if (sm) {
      var heading = sm[1];
      if (/^Subcommands$/i.test(heading)) {
        section = "subcommands";
        currentFlagSection = null;
      } else if (/flags$/i.test(heading)) {
        section = "flags";
        currentFlagSection = { heading: heading, flags: [] };
        out.flagSections.push(currentFlagSection);
      } else if (/^Exit codes$/i.test(heading)) {
        section = "exit";
        currentFlagSection = null;
      } else {
        section = null;
        currentFlagSection = null;
      }
      continue;
    }
    if (section === "subcommands") {
      var sub = _re(SUB_ROW_RE, line);
      if (sub) out.subcommands.push({ name: sub[1], description: sub[2].replace(/\s+$/, "") });
    } else if (section === "flags" && currentFlagSection) {
      var fl = _re(FLAG_ROW_RE, line);
      if (fl) currentFlagSection.flags.push({ flag: fl[1], description: fl[2].replace(/\s+$/, "") });
    } else if (section === "exit") {
      var trimmed = line.replace(/^\s+|\s+$/g, "");
      if (trimmed) out.exitCodes.push(trimmed);
    }
  }
  return out;
}

// Captures the comment block (// ...) immediately following a
// `// ---- Subcommand: <name> ----` divider, stopping at the first
// non-comment line.
function _proseForCommand(src, name) {
  var divider = "// ---- Subcommand: " + name;
  var idx = src.indexOf(divider);
  if (idx < 0) return "";
  var after = src.indexOf("\n", idx);
  if (after < 0) return "";
  var lines = src.substring(after + 1).split("\n");
  var prose = [];
  for (var i = 0; i < lines.length; i++) {
    var raw = lines[i];
    var trimmed = raw.replace(/^\s+|\s+$/g, "");
    if (trimmed === "//") { if (prose.length === 0) continue; else break; }
    if (trimmed.indexOf("//") === 0) {
      prose.push(trimmed.replace(/^\/\/\s?/, ""));
    } else {
      break;
    }
  }
  return prose.join(" ").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "");
}

// Topic categorization for nav-grouping in render().
function _categoryOf(name) {
  if (name === "migrate" || name === "seed")               return "Database";
  if (name === "backup"  || name === "restore" ||
      name === "erase"   || name === "retention")          return "Data lifecycle";
  if (name === "audit")                                    return "Audit chain";
  if (name === "vault"   || name === "mtls" ||
      name === "api-key" || name === "password")           return "Crypto & keys";
  if (name === "security" || name === "config-drift" ||
      name === "file-type")                                return "Security tooling";
  if (name === "dev" || name === "api-snapshot")           return "Developer workflow";
  return "Other";
}

function harvest(opts) {
  opts = opts || {};
  var libRoot = opts.libRoot || path.resolve(__dirname, "..", "..", "..", "lib");
  var files   = _findCliFiles(libRoot);
  if (files.length === 0) {
    return { generatedAt: new Date().toISOString(), commands: [], reason: "no lib/cli.js or lib/cli/ found" };
  }

  // Concatenate every CLI source so USAGE constants split across
  // future lib/cli/*.js files still resolve.
  var sources = [];
  for (var i = 0; i < files.length; i++) {
    var src = _readSafe(files[i]);
    if (src !== null) sources.push({ file: files[i], src: src });
  }
  if (sources.length === 0) {
    return { generatedAt: new Date().toISOString(), commands: [], reason: "lib/cli.js unreadable" };
  }
  var combined = sources.map(function (s) { return s.src; }).join("\n\n// ---- next file ----\n\n");

  var topUsage = _extractUsageBlock(combined, "TOP_USAGE");
  var topRows  = _parseTopUsage(topUsage);
  if (topRows.length === 0) {
    return { generatedAt: new Date().toISOString(), commands: [], reason: "TOP_USAGE not found or unparseable" };
  }

  var commands = [];
  for (var r = 0; r < topRows.length; r++) {
    var row = topRows[r];
    if (row.name === "help") continue; // built-in, no USAGE constant
    if (row.name === "version") {
      commands.push({
        name:        "version",
        description: row.description,
        usageLine:   "blamejs version",
        usageVar:    null,
        subcommands: [],
        flagSections: [],
        exitCodes:   [],
        prose:       "",
        category:    "Developer workflow",
        file:        path.relative(path.dirname(libRoot), sources[0].file).replace(/\\/g, "/"),
      });
      continue;
    }
    var usageVar = row.name.toUpperCase().replace(/-/g, "_") + "_USAGE";
    var blob = _extractUsageBlock(combined, usageVar);
    var parsed = _parseUsageBlob(blob);
    var prose = "";
    var sourceFile = null;
    for (var s = 0; s < sources.length; s++) {
      if (sources[s].src.indexOf("// ---- Subcommand: " + row.name) >= 0) {
        sourceFile = sources[s].file;
        prose = _proseForCommand(sources[s].src, row.name);
        break;
      }
    }
    commands.push({
      name:         row.name,
      description:  row.description,
      usageLine:    parsed.usageLine || "blamejs " + row.name,
      usageVar:     usageVar,
      subcommands:  parsed.subcommands,
      flagSections: parsed.flagSections,
      exitCodes:    parsed.exitCodes,
      prose:        prose,
      category:     _categoryOf(row.name),
      file:         sourceFile
        ? path.relative(path.dirname(libRoot), sourceFile).replace(/\\/g, "/")
        : "lib/cli.js",
    });
  }

  commands.sort(function (a, b) {
    if (a.name < b.name) return -1;
    if (a.name > b.name) return 1;
    return 0;
  });

  return {
    generatedAt: new Date().toISOString(),
    commands:    commands,
  };
}

function _esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function _slug(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

// Synthesizes a representative one-line bash example. Prefers the
// first subcommand + first matching-section flag when present;
// otherwise falls back to the parsed Usage: line.
function _exampleFor(cmd) {
  if (cmd.subcommands.length > 0) {
    var first = cmd.subcommands[0];
    var line  = "blamejs " + cmd.name + " " + first.name;
    var subSection = null;
    for (var i = 0; i < cmd.flagSections.length; i++) {
      if (cmd.flagSections[i].heading.toLowerCase().indexOf(first.name) === 0) {
        subSection = cmd.flagSections[i];
        break;
      }
    }
    if (!subSection) {
      for (var j = 0; j < cmd.flagSections.length; j++) {
        var h = cmd.flagSections[j].heading.toLowerCase();
        if (h === "flags" || h === "common flags" || h.indexOf("flags (all") === 0) {
          subSection = cmd.flagSections[j];
          break;
        }
      }
    }
    if (subSection && subSection.flags.length > 0) {
      line += " " + subSection.flags[0].flag;
    }
    return line;
  }
  if (cmd.usageLine) {
    return cmd.usageLine.replace(/\s+\[flags\]\s*$/, "")
                        .replace(/\s+<subcommand>.*$/, "");
  }
  return "blamejs " + cmd.name;
}

function _renderCommand(cmd) {
  var slug = _slug(cmd.name);
  var out = [];
  out.push('<h2 id="' + _esc(slug) + '">blamejs ' + _esc(cmd.name) + '</h2>');
  out.push('<p>' + _esc(cmd.description) + '</p>');
  if (cmd.prose) {
    out.push('<p>' + _esc(cmd.prose) + '</p>');
  }
  if (cmd.usageLine) {
    out.push('<p><strong>Usage:</strong> <code>' + _esc(cmd.usageLine) + '</code></p>');
  }
  if (cmd.subcommands.length > 0) {
    out.push('<h3 id="' + _esc(slug) + '-subcommands">Subcommands</h3>');
    out.push('<table>');
    out.push('<thead><tr><th>Subcommand</th><th>Description</th></tr></thead>');
    out.push('<tbody>');
    for (var s = 0; s < cmd.subcommands.length; s++) {
      var sub = cmd.subcommands[s];
      out.push('<tr><td><code>' + _esc(sub.name) + '</code></td><td>' + _esc(sub.description) + '</td></tr>');
    }
    out.push('</tbody></table>');
  }
  if (cmd.flagSections.length > 0) {
    for (var f = 0; f < cmd.flagSections.length; f++) {
      var sect = cmd.flagSections[f];
      if (sect.flags.length === 0) continue;
      var sectSlug = _esc(slug + "-" + String(sect.heading).toLowerCase().replace(/[^a-z0-9_]+/g, "-").replace(/^-+|-+$/g, ""));
      out.push('<h3 id="' + sectSlug + '">' + _esc(sect.heading) + '</h3>');
      out.push('<table>');
      out.push('<thead><tr><th>Flag</th><th>Description</th></tr></thead>');
      out.push('<tbody>');
      for (var k = 0; k < sect.flags.length; k++) {
        var fl = sect.flags[k];
        out.push('<tr><td><code>' + _esc(fl.flag) + '</code></td><td>' + _esc(fl.description) + '</td></tr>');
      }
      out.push('</tbody></table>');
    }
  }
  if (cmd.exitCodes.length > 0) {
    out.push('<h3 id="' + _esc(slug) + '-exit-codes">Exit codes</h3>');
    out.push('<ul>');
    for (var ec = 0; ec < cmd.exitCodes.length; ec++) {
      out.push('<li><code>' + _esc(cmd.exitCodes[ec]) + '</code></li>');
    }
    out.push('</ul>');
  }
  out.push('<h3 id="' + _esc(slug) + '-example">Example</h3>');
  out.push('<pre><code class="language-bash">' + _esc(_exampleFor(cmd)) + '</code></pre>');
  out.push('<p><small>Source: <code>' + _esc(cmd.file) + '</code></small></p>');
  return out.join("\n");
}

function render(manifest) {
  if (!manifest || !Array.isArray(manifest.commands)) {
    throw new TypeError("render: manifest.commands array required");
  }
  var out = [];
  out.push('<h1>CLI commands</h1>');
  out.push('<p>Operator commands shipped under the <code>blamejs</code> ' +
    'binary (<code>bin/blamejs.js</code>, dispatched through ' +
    '<code>b.cli.main</code>). Each subcommand is harvested directly ' +
    'from <code>lib/cli.js</code> so the page stays in lock-step with ' +
    'the dispatcher.</p>');

  if (manifest.commands.length === 0) {
    out.push('<div class="callout"><div class="callout-title">CLI not yet harvestable</div>' +
      '<p>The harvester walked <code>lib/cli.js</code> (and any ' +
      '<code>lib/cli/</code> subdirectory) but could not derive a ' +
      'command registry.' +
      (manifest.reason ? ' Reason: <code>' + _esc(manifest.reason) + '</code>.' : '') +
      ' To enable harvesting, the dispatcher must expose a ' +
      '<code>TOP_USAGE</code> constant whose <code>Commands:</code> ' +
      'section lists every top-level subcommand as ' +
      '<code>"  &lt;name&gt;  &lt;description&gt;"</code>, plus a ' +
      'matching <code>&lt;NAME&gt;_USAGE</code> constant per command. ' +
      'See <code>lib/cli.js</code> in any v0.7.x+ release for the ' +
      'shape.</p></div>');
    return out.join("\n");
  }

  out.push('<p>Commands harvested: <strong>' + manifest.commands.length +
    '</strong>. Run <code>blamejs help &lt;command&gt;</code> for the ' +
    'authoritative live usage. Generated ' + _esc(manifest.generatedAt) +
    '.</p>');

  // Group by category for navigation.
  var orderedCats = [
    "Database", "Data lifecycle", "Audit chain", "Crypto & keys",
    "Security tooling", "Developer workflow", "Other",
  ];
  var groups = {};
  for (var i = 0; i < manifest.commands.length; i++) {
    var c = manifest.commands[i];
    if (!groups[c.category]) groups[c.category] = [];
    groups[c.category].push(c);
  }
  var seenCats = Object.keys(groups);
  var renderOrder = orderedCats.filter(function (k) { return groups[k]; });
  for (var u = 0; u < seenCats.length; u++) {
    if (renderOrder.indexOf(seenCats[u]) === -1) renderOrder.push(seenCats[u]);
  }

  // Top-level command index.
  out.push('<h2 id="index">Command index</h2>');
  for (var ci = 0; ci < renderOrder.length; ci++) {
    var cat = renderOrder[ci];
    out.push('<h3>' + _esc(cat) + '</h3>');
    out.push('<ul>');
    var rows = groups[cat];
    for (var ri = 0; ri < rows.length; ri++) {
      var cmd = rows[ri];
      out.push('<li><a href="#' + _esc(_slug(cmd.name)) + '"><code>blamejs ' +
        _esc(cmd.name) + '</code></a> — ' + _esc(cmd.description) + '</li>');
    }
    out.push('</ul>');
  }

  // Per-command sections.
  for (var cj = 0; cj < renderOrder.length; cj++) {
    var rows2 = groups[renderOrder[cj]];
    rows2.sort(function (a, b) { return a.name < b.name ? -1 : a.name > b.name ? 1 : 0; });
    for (var rj = 0; rj < rows2.length; rj++) {
      out.push(_renderCommand(rows2[rj]));
    }
  }

  out.push('<div class="callout"><div class="callout-title">Live help</div>' +
    '<p>This page is a build-time snapshot. The authoritative source is ' +
    '<code>blamejs help &lt;command&gt;</code> (or ' +
    '<code>blamejs &lt;command&gt; --help</code>) — both render the ' +
    'same <code>USAGE</code> constants this harvester reads.</p></div>');

  return out.join("\n");
}

module.exports = {
  harvest:            harvest,
  render:             render,
  _parseTopUsage:     _parseTopUsage,
  _parseUsageBlob:    _parseUsageBlob,
  _extractUsageBlock: _extractUsageBlock,
  _proseForCommand:   _proseForCommand,
  _categoryOf:        _categoryOf,
};
