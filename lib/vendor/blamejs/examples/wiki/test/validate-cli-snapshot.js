"use strict";
/**
 * CLI surface snapshot — parallel to api-snapshot + env-snapshot.
 *
 * Three sides need to stay aligned for CLI documentation to be useful:
 *
 *   1. lib/cli.js — the actual CLI surface (subcommands + per-subcommand
 *      flags, sourced from each *_USAGE constant).
 *   2. README.md — the CLI section that operators read first.
 *   3. The wiki — primitive docs that reference CLI invocations
 *      ("blamejs vault rotate ..." in crypto-vault.html, etc.).
 *
 * Drift kills operator trust. If a CLI flag lands in lib/cli.js but
 * README never mentions it, operators can't discover it. If README
 * documents `blamejs foo bar` but the CLI parser doesn't dispatch
 * "foo", operators copy a broken command.
 *
 * This validator:
 *   - Parses lib/cli.js for the subcommand list (from TOP_USAGE) and
 *     each subcommand's USAGE constant (subcommands + flags).
 *   - Parses README.md's CLI section for documented `blamejs <cmd>`
 *     invocations.
 *   - Walks the wiki seeders for any `blamejs <cmd>` mentions.
 *   - Captures the union as examples/wiki/cli-snapshot.json.
 *   - Fails on drift OR cli-only / readme-only gaps.
 *
 * Update workflow: BLAMEJS_UPDATE_CLI_SNAPSHOT=1
 *   node examples/wiki/test/validate-cli-snapshot.js
 */
var fs = require("node:fs");
var path = require("node:path");

var REPO_ROOT     = path.resolve(__dirname, "..", "..", "..");
var WIKI_ROOT     = path.resolve(__dirname, "..");
var SNAPSHOT_PATH = path.join(WIKI_ROOT, "cli-snapshot.json");
var CLI_PATH      = path.join(REPO_ROOT, "lib", "cli.js");
var README_PATH   = path.join(REPO_ROOT, "README.md");

// Subcommands documented in lib/cli.js but not expected to appear in
// README's CLI table (e.g. internal-only / dev-only commands).
var CLI_ONLY_ALLOWED = {
  "help":    "meta-command, not part of the operator surface",
  "version": "trivial; documented as `--version` flag",
};

// Subcommands referenced in README/wiki but not implemented (rare —
// usually only during a deprecation window).
var README_ONLY_ALLOWED = {
};

// `cmd sub` pairs that appear in README/wiki but aren't real subcommands —
// usually because the second token is part of a flag value or filename
// the validator can't classify out of context. Keep this minimal.
var DOC_PAIR_ALLOWED = {
};

function _parseUsageBlock(text, defaultCmd) {
  var lines = text.split(/\r?\n/);
  var cmdMatch = /^Usage:\s+blamejs\s+(\S+)/.exec(lines[0] || "");
  var cmd = cmdMatch ? cmdMatch[1] : defaultCmd;
  var subcommands = [];
  var flags = [];
  var section = null;
  for (var i = 1; i < lines.length; i++) {
    var line = lines[i];
    if (/^Subcommands:\s*$/i.test(line))   { section = "sub";  continue; }
    if (/^Flags:\s*$/i.test(line))          { section = "flag"; continue; }
    if (/^Common flags:\s*$/i.test(line))   { section = "flag"; continue; }
    if (/^[A-Z]/.test(line))                { section = null;   continue; }
    if (line.trim().length === 0)           { section = null;   continue; }
    if (section === "sub") {
      // Real subcommand line: exactly 2 leading spaces (not 3+),
      // a lowercase token, then 4+ spaces, then a Capital-letter
      // description. Continuation lines that quote prose get extra
      // indentation (column-aligned to the description start) and
      // start with lowercase — the Capital filter rules them out.
      var subM = /^ {2}([a-z][a-z0-9-]*)\s{2,}[A-Z]/.exec(line);
      if (subM) subcommands.push(subM[1]);
    } else if (section === "flag") {
      // Same shape: exactly 2-space indent + --flag + 2+ spaces + Capital.
      var flagM = /^ {2}(--[a-z][a-z0-9-]*)(?:\s+<[^>]+>)?\s{2,}[A-Z]/.exec(line);
      if (flagM) flags.push(flagM[1]);
    }
  }
  return { cmd: cmd, subcommands: subcommands.sort(), flags: flags.sort() };
}

function captureCliSurface() {
  var src = fs.readFileSync(CLI_PATH, "utf8");
  var usageRe = /var\s+([A-Z_]+_USAGE)\s*=\s*\[\s*([\s\S]*?)\s*\]\.join\(/g;
  var m;
  var cmds = {};
  while ((m = usageRe.exec(src)) !== null) {
    var name = m[1];
    if (name === "TOP_USAGE") continue;
    var entries = [];
    var entryRe = /"((?:[^"\\]|\\.)*)"/g;
    var em;
    while ((em = entryRe.exec(m[2])) !== null) {
      entries.push(em[1].replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\\\/g, "\\"));
    }
    var defaultCmd = name.replace(/_USAGE$/, "").toLowerCase().replace(/_/g, "-");
    var parsed = _parseUsageBlock(entries.join("\n"), defaultCmd);
    cmds[parsed.cmd] = { subcommands: parsed.subcommands, flags: parsed.flags };
  }
  var topMatch = /var\s+TOP_USAGE\s*=\s*\[\s*([\s\S]*?)\s*\]\.join\(/.exec(src);
  var topCommands = [];
  if (topMatch) {
    var topEntryRe = /"((?:[^"\\]|\\.)*)"/g;
    var tem;
    while ((tem = topEntryRe.exec(topMatch[1])) !== null) {
      var line = tem[1];
      var cm = /^\s+([a-z][a-z0-9-]*)\s+\S/.exec(line);
      if (cm) topCommands.push(cm[1]);
    }
  }
  return { topCommands: topCommands.sort(), perCommand: cmds };
}

function _findCliInvocations(text) {
  var found = new Set();
  var re = /\bblamejs\s+([a-z][a-z0-9-]*)\b/g;
  var m;
  while ((m = re.exec(text)) !== null) {
    found.add(m[1]);
  }
  return Array.from(found).sort();
}

// Parse `blamejs <cmd> <sub>` two-token pairs out of a chunk. Skips
// the second token when it begins with `-` (a flag) or `<` / `[`
// (a usage placeholder). Validator uses these to verify that
// documented subcommand invocations actually exist in lib/cli.js.
function _findCliPairs(text) {
  var found = new Set();
  var re = /\bblamejs\s+([a-z][a-z0-9-]*)\s+([a-z][a-z0-9-]*)\b/g;
  var m;
  while ((m = re.exec(text)) !== null) {
    found.add(m[1] + ":" + m[2]);
  }
  return Array.from(found).sort();
}

function captureReadmeCommands() {
  var src = fs.readFileSync(README_PATH, "utf8");
  var cliSectionMatch = /##\s+CLI\b([\s\S]*?)(?=\n##\s)/.exec(src);
  if (!cliSectionMatch) return { commands: [], pairs: [] };
  return {
    commands: _findCliInvocations(cliSectionMatch[1]),
    pairs:    _findCliPairs(cliSectionMatch[1]),
  };
}

function _walkWiki(dir, results) {
  var stat;
  try { stat = fs.statSync(dir); } catch (_e) { return; }
  if (stat.isDirectory()) {
    var skip = ["node_modules", "data", "data-e2e", "public", "test"];
    var entries = fs.readdirSync(dir);
    for (var i = 0; i < entries.length; i++) {
      if (skip.indexOf(entries[i]) !== -1) continue;
      _walkWiki(path.join(dir, entries[i]), results);
    }
    return;
  }
  if (!/\.(js|html)$/.test(dir)) return;
  var src = fs.readFileSync(dir, "utf8");
  // Only count CLI mentions inside code blocks — prose like "blamejs is
  // a Node framework" matches the bare regex but isn't a real CLI ref.
  // Code-block markers in wiki sources: <pre><code>...</code></pre>,
  // inline <code>...</code>, and (in raw .html) `...` backticks.
  var codeChunks = [];
  var preRe = /<pre><code[^>]*>([\s\S]*?)<\/code><\/pre>/g;
  var inlineRe = /<code[^>]*>([\s\S]*?)<\/code>/g;
  var backtickRe = /`([^`\n]+)`/g;
  var m;
  while ((m = preRe.exec(src))    !== null) codeChunks.push(m[1]);
  while ((m = inlineRe.exec(src)) !== null) codeChunks.push(m[1]);
  while ((m = backtickRe.exec(src)) !== null) codeChunks.push(m[1]);
  codeChunks.forEach(function (chunk) {
    _findCliInvocations(chunk).forEach(function (c) { results.commands.add(c); });
    _findCliPairs(chunk).forEach(function (p) { results.pairs.add(p); });
  });
}

function captureWikiCommands() {
  var acc = { commands: new Set(), pairs: new Set() };
  ["seeders", "views"].forEach(function (sub) {
    _walkWiki(path.join(WIKI_ROOT, sub), acc);
  });
  return {
    commands: Array.from(acc.commands).sort(),
    pairs:    Array.from(acc.pairs).sort(),
  };
}

function captureSnapshot() {
  var cli   = captureCliSurface();
  var rdme  = captureReadmeCommands();
  var wiki  = captureWikiCommands();
  return {
    topCommands: cli.topCommands,
    perCommand:  cli.perCommand,
    readme:      rdme.commands,
    readmePairs: rdme.pairs,
    wiki:        wiki.commands,
    wikiPairs:   wiki.pairs,
  };
}

function _arrSubtract(a, b) {
  var bSet = new Set(b);
  return (a || []).filter(function (x) { return !bSet.has(x); });
}

function compareSnapshot(captured) {
  var stored;
  try { stored = JSON.parse(fs.readFileSync(SNAPSHOT_PATH, "utf8")); }
  catch (_e) { return { initialized: false, drift: [], gaps: [] }; }

  var drift = [];
  var addedTop   = _arrSubtract(captured.topCommands, stored.topCommands);
  var removedTop = _arrSubtract(stored.topCommands,   captured.topCommands);
  if (addedTop.length   > 0) drift.push({ field: "topCommands", kind: "added",   keys: addedTop });
  if (removedTop.length > 0) drift.push({ field: "topCommands", kind: "removed", keys: removedTop });
  var allCmds = new Set(Object.keys(captured.perCommand)
                              .concat(Object.keys(stored.perCommand || {})));
  allCmds.forEach(function (cmd) {
    var c = captured.perCommand[cmd] || { subcommands: [], flags: [] };
    var s = (stored.perCommand && stored.perCommand[cmd]) || { subcommands: [], flags: [] };
    var addedSub   = _arrSubtract(c.subcommands, s.subcommands);
    var removedSub = _arrSubtract(s.subcommands, c.subcommands);
    var addedFlag   = _arrSubtract(c.flags, s.flags);
    var removedFlag = _arrSubtract(s.flags, c.flags);
    if (addedSub.length   > 0) drift.push({ field: cmd + ".subcommands", kind: "added",   keys: addedSub });
    if (removedSub.length > 0) drift.push({ field: cmd + ".subcommands", kind: "removed", keys: removedSub });
    if (addedFlag.length   > 0) drift.push({ field: cmd + ".flags",      kind: "added",   keys: addedFlag });
    if (removedFlag.length > 0) drift.push({ field: cmd + ".flags",      kind: "removed", keys: removedFlag });
  });
  var addedReadme   = _arrSubtract(captured.readme, stored.readme);
  var removedReadme = _arrSubtract(stored.readme,   captured.readme);
  if (addedReadme.length   > 0) drift.push({ field: "readme", kind: "added",   keys: addedReadme });
  if (removedReadme.length > 0) drift.push({ field: "readme", kind: "removed", keys: removedReadme });
  var addedWiki   = _arrSubtract(captured.wiki, stored.wiki);
  var removedWiki = _arrSubtract(stored.wiki,   captured.wiki);
  if (addedWiki.length   > 0) drift.push({ field: "wiki", kind: "added",   keys: addedWiki });
  if (removedWiki.length > 0) drift.push({ field: "wiki", kind: "removed", keys: removedWiki });
  var addedReadmePairs   = _arrSubtract(captured.readmePairs, stored.readmePairs || []);
  var removedReadmePairs = _arrSubtract(stored.readmePairs || [], captured.readmePairs);
  if (addedReadmePairs.length   > 0) drift.push({ field: "readmePairs", kind: "added",   keys: addedReadmePairs });
  if (removedReadmePairs.length > 0) drift.push({ field: "readmePairs", kind: "removed", keys: removedReadmePairs });
  var addedWikiPairs   = _arrSubtract(captured.wikiPairs, stored.wikiPairs || []);
  var removedWikiPairs = _arrSubtract(stored.wikiPairs || [], captured.wikiPairs);
  if (addedWikiPairs.length   > 0) drift.push({ field: "wikiPairs", kind: "added",   keys: addedWikiPairs });
  if (removedWikiPairs.length > 0) drift.push({ field: "wikiPairs", kind: "removed", keys: removedWikiPairs });

  var gaps = [];
  var readmeSet = new Set(captured.readme);
  captured.topCommands.forEach(function (cmd) {
    if (CLI_ONLY_ALLOWED[cmd]) return;
    if (!readmeSet.has(cmd)) gaps.push({ side: "cli-not-in-readme", key: cmd });
  });
  var topSet = new Set(captured.topCommands);
  captured.readme.forEach(function (cmd) {
    if (README_ONLY_ALLOWED[cmd]) return;
    if (!topSet.has(cmd)) gaps.push({ side: "readme-not-in-cli", key: cmd });
  });
  // Wiki gaps — a wiki page promising `blamejs <cmd>` that the CLI
  // doesn't dispatch is misleading documentation. Catches the
  // common drift where a primitive's wiki page references a CLI
  // command that was planned but never shipped.
  captured.wiki.forEach(function (cmd) {
    if (README_ONLY_ALLOWED[cmd]) return;
    if (!topSet.has(cmd)) gaps.push({ side: "wiki-not-in-cli", key: cmd });
  });
  // Subcommand-pair gaps — a wiki / README invocation `blamejs <cmd>
  // <sub>` where <cmd> is a real top command but <sub> is not in
  // perCommand[<cmd>].subcommands. Catches drift where a USAGE block
  // ships verify-bundle but the wiki documents verify-signing, or
  // where a subcommand was renamed but the docs still point at the
  // old name.
  function _checkPair(side, key) {
    if (DOC_PAIR_ALLOWED[key]) return;
    var parts = key.split(":");
    var cmd = parts[0], sub = parts[1];
    if (!topSet.has(cmd)) return;                         // top-cmd gap fires the alert; no double report
    var entry = captured.perCommand[cmd];
    if (!entry || !entry.subcommands) return;             // no USAGE block (e.g. `version`); pair shape doesn't apply
    if (entry.subcommands.length === 0) return;           // CLI takes flags only, not subcommands; second token is a positional, not a subcmd name
    if (entry.subcommands.indexOf(sub) === -1) {
      gaps.push({ side: side, key: key, validSubs: entry.subcommands.slice() });
    }
  }
  (captured.readmePairs || []).forEach(function (p) { _checkPair("readme-pair-not-in-cli", p); });
  (captured.wikiPairs   || []).forEach(function (p) { _checkPair("wiki-pair-not-in-cli",   p); });
  return { initialized: true, drift: drift, gaps: gaps, stored: stored };
}

function writeSnapshot(captured) {
  fs.writeFileSync(SNAPSHOT_PATH, JSON.stringify(captured, null, 2) + "\n", "utf8");
}

module.exports = {
  captureSnapshot:  captureSnapshot,
  compareSnapshot:  compareSnapshot,
  writeSnapshot:    writeSnapshot,
  SNAPSHOT_PATH:    SNAPSHOT_PATH,
  CLI_ONLY_ALLOWED:    CLI_ONLY_ALLOWED,
  README_ONLY_ALLOWED: README_ONLY_ALLOWED,
};

if (require.main === module) {
  var captured = captureSnapshot();
  if (process.env.BLAMEJS_UPDATE_CLI_SNAPSHOT === "1") {
    writeSnapshot(captured);
    console.log("[cli-snapshot] wrote " + SNAPSHOT_PATH);
    console.log("  topCommands:    " + captured.topCommands.length);
    console.log("  perCommand:     " + Object.keys(captured.perCommand).length + " usage blocks");
    console.log("  readme refs:    " + captured.readme.length + " (cmds), " + captured.readmePairs.length + " (pairs)");
    console.log("  wiki refs:      " + captured.wiki.length + " (cmds), " + captured.wikiPairs.length + " (pairs)");
    process.exit(0);
  }
  var verdict = compareSnapshot(captured);
  if (!verdict.initialized) {
    console.error("[cli-snapshot] snapshot file missing at " + SNAPSHOT_PATH);
    console.error("  Create with: BLAMEJS_UPDATE_CLI_SNAPSHOT=1 node " +
                  path.relative(process.cwd(), __filename));
    process.exit(1);
  }
  var failed = false;
  if (verdict.drift.length > 0) {
    console.error("[cli-snapshot] DRIFT - committed snapshot does not match capture:");
    verdict.drift.forEach(function (d) {
      var sign = d.kind === "added" ? "+" : "-";
      console.error("  " + sign + " " + d.field + ": " + d.keys.join(", "));
    });
    failed = true;
  }
  if (verdict.gaps.length > 0) {
    console.error("[cli-snapshot] GAPS - CLI surface vs documentation mismatch:");
    verdict.gaps.forEach(function (g) {
      if (g.side === "cli-not-in-readme") {
        console.error("  CLI implements `blamejs " + g.key + "` but README's CLI section never mentions it");
        console.error("    -> add to README.md ## CLI table");
      } else if (g.side === "wiki-not-in-cli") {
        console.error("  Wiki page references `blamejs " + g.key + "` but the CLI parser does not dispatch it");
        console.error("    -> remove the misleading reference from the wiki, OR add the subcommand to lib/cli.js");
      } else if (g.side === "wiki-pair-not-in-cli") {
        var wp = g.key.split(":");
        console.error("  Wiki page references `blamejs " + wp[0] + " " + wp[1] + "` but `" + wp[1] + "` is not a real subcommand of `" + wp[0] + "`");
        console.error("    valid subcommands: " + g.validSubs.join(", "));
        console.error("    -> fix the wiki to use a real subcommand, OR add `" + wp[1] + "` to lib/cli.js " + wp[0].toUpperCase() + "_USAGE");
      } else if (g.side === "readme-pair-not-in-cli") {
        var rp = g.key.split(":");
        console.error("  README documents `blamejs " + rp[0] + " " + rp[1] + "` but `" + rp[1] + "` is not a real subcommand of `" + rp[0] + "`");
        console.error("    valid subcommands: " + g.validSubs.join(", "));
        console.error("    -> fix README, OR add `" + rp[1] + "` to lib/cli.js " + rp[0].toUpperCase() + "_USAGE");
      } else {
        console.error("  README's CLI section documents `blamejs " + g.key + "` but the CLI parser does not dispatch it");
        console.error("    -> remove from README, OR add the subcommand to lib/cli.js");
      }
    });
    failed = true;
  }
  if (failed) {
    console.error("[cli-snapshot] fix and re-run, OR run with BLAMEJS_UPDATE_CLI_SNAPSHOT=1 to accept.");
    process.exit(1);
  }
  console.log("[cli-snapshot] OK - " + captured.topCommands.length + " top-level commands, " +
              Object.keys(captured.perCommand).length + " usage blocks, " +
              captured.readme.length + " README refs, " +
              captured.wiki.length + " wiki refs");
  process.exit(0);
}
