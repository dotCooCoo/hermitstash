"use strict";
// scripts/gen-migrating.js — generate MIGRATING.md from deprecate() calls
// across lib/. Walks the tree, finds every `deprecate.warn|wrap|alias`
// invocation, extracts the opts literal, groups by removeIn major.
//
// Re-run before each release; the file is committed so operators can
// read the diff against the prior tag.
//
// Limitation: opts must be an object literal (the common case in this
// codebase). Calls that pass a variable as opts won't be captured —
// the script logs them with a [gen-migrating] note and the entry is
// skipped. Switch to a module-hook capture if that ever becomes the
// dominant pattern.

var fs = require("node:fs");
var path = require("node:path");

var ROOT      = path.resolve(__dirname, "..");
var LIB_DIR   = path.join(ROOT, "lib");
var TARGET    = path.join(ROOT, "MIGRATING.md");

function _walk(dir, out) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name !== "vendor") _walk(full, out);
    } else if (e.isFile() && e.name.endsWith(".js")) {
      out.push(full);
    }
  });
  return out;
}

// Find the closing brace of an object literal that starts at index i
// (where src[i] === "{"). Tracks nesting + quoted strings + escapes.
// Returns the index AFTER the closing brace, or -1 if unterminated.
function _findObjectEnd(src, i) {
  var depth = 0;
  var inStr = null;
  var esc = false;
  for (; i < src.length; i++) {
    var c = src[i];
    if (esc) { esc = false; continue; }
    if (inStr) {
      if (c === "\\") esc = true;
      else if (c === inStr) inStr = null;
      continue;
    }
    if (c === "'" || c === "\"" || c === "`") { inStr = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

function _evalOpts(src) {
  try { return Function("return " + src)(); }
  catch (_e) { return null; }
}

function _extractDeprecations(src, fileLabel) {
  var out = [];

  // .warn("name", { ... })
  for (var m of src.matchAll(/(?:^|[^.\w])deprecate\.warn\s*\(\s*"([^"]+)"\s*,\s*\{/g)) {
    var braceAt = m.index + m[0].length - 1;
    var end = _findObjectEnd(src, braceAt);
    if (end < 0) continue;
    var opts = _evalOpts(src.slice(braceAt, end));
    if (!opts) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.warn(\"" + m[1] + "\")\n");
      continue;
    }
    out.push({ kind: "warn", name: m[1], opts: opts });
  }

  // .wrap(<fn>, "name", { ... })
  for (var w of src.matchAll(/(?:^|[^.\w])deprecate\.wrap\s*\(/g)) {
    var startW = w.index + w[0].length;
    var nameMatchW = src.slice(startW).match(/"([^"]+)"\s*,/);
    if (!nameMatchW) continue;
    var afterNameW = startW + nameMatchW.index + nameMatchW[0].length;
    var openBraceW = src.indexOf("{", afterNameW);
    if (openBraceW < 0) continue;
    var endW = _findObjectEnd(src, openBraceW);
    if (endW < 0) continue;
    var optsW = _evalOpts(src.slice(openBraceW, endW));
    if (!optsW) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.wrap(\"" + nameMatchW[1] + "\")\n");
      continue;
    }
    out.push({ kind: "wrap", name: nameMatchW[1], opts: optsW });
  }

  // .alias(<obj>, "old", "new", { ... })
  for (var a of src.matchAll(/(?:^|[^.\w])deprecate\.alias\s*\(/g)) {
    var startA = a.index + a[0].length;
    var aliasMatchA = src.slice(startA).match(/"([^"]+)"\s*,\s*"([^"]+)"\s*,/);
    if (!aliasMatchA) continue;
    var afterAliasA = startA + aliasMatchA.index + aliasMatchA[0].length;
    var openBraceA = src.indexOf("{", afterAliasA);
    if (openBraceA < 0) continue;
    var endA = _findObjectEnd(src, openBraceA);
    if (endA < 0) continue;
    var optsA = _evalOpts(src.slice(openBraceA, endA));
    if (!optsA) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.alias(\"" + aliasMatchA[1] + "\")\n");
      continue;
    }
    out.push({ kind: "alias", name: aliasMatchA[1], renamedTo: aliasMatchA[2], opts: optsA });
  }

  return out;
}

function _majorOf(version) {
  var m = String(version || "").match(/^(\d+)\.(\d+)/);
  if (!m) return null;
  return Number(m[1]) === 0 ? "v0.x" : "v" + m[1] + ".x";
}

function _gather() {
  var files = _walk(LIB_DIR, []);
  var entries = [];
  files.forEach(function (f) {
    var src = fs.readFileSync(f, "utf8");
    var rel = path.relative(ROOT, f).replace(/\\/g, "/");
    _extractDeprecations(src, rel).forEach(function (d) {
      if (!d.opts.since || !d.opts.removeIn) {
        process.stderr.write("[gen-migrating] " + rel + ": " + d.kind + " call for \"" + d.name + "\" missing since/removeIn — skipped\n");
        return;
      }
      entries.push({
        name:      d.name,
        kind:      d.kind,
        since:     d.opts.since,
        removeIn:  d.opts.removeIn,
        message:   d.opts.message || null,
        hint:      d.opts.hint || null,
        renamedTo: d.renamedTo || null,
        file:      rel,
      });
    });
  });
  return entries;
}

function _build() {
  var entries = _gather();
  var byRemove = new Map();
  entries.forEach(function (e) {
    var major = _majorOf(e.removeIn);
    if (!major) return;
    if (!byRemove.has(major)) byRemove.set(major, []);
    byRemove.get(major).push(e);
  });

  var lines = [];
  lines.push("# Migrating");
  lines.push("");
  lines.push("Operator-facing migration recipes per breaking change. The bulk of this file is auto-generated from `deprecate()`-marked surface in the framework — the running app warns about each (with `BLAMEJS_DEPRECATIONS=warn` set, or by default outside production) before the noted removal version. Re-run `node scripts/gen-migrating.js` before each release; the file is committed so operators can diff it against the prior tag.");
  lines.push("");
  lines.push("**Out-of-band breaking changes** (schema breaks, config-shape changes, on-disk format breaks) cannot be expressed as `deprecate()` calls because there's no in-process runtime to warn from. They're hardcoded in the OUT_OF_BAND_BREAKS table inside `scripts/gen-migrating.js` so the operator sees the full upgrade path here without needing to grep CHANGELOG.");
  lines.push("");

  if (entries.length === 0) {
    lines.push("## No active deprecations");
    lines.push("");
    lines.push("The framework has no `deprecate()`-marked surface awaiting removal.");
    lines.push("");
    _appendOutOfBand(lines);
    return lines.join("\n");
  }

  var majors = Array.from(byRemove.keys()).sort();
  majors.forEach(function (m) {
    lines.push("## Removed in " + m);
    lines.push("");
    var rows = byRemove.get(m).slice().sort(function (a, b) {
      if (a.since !== b.since) return a.since < b.since ? -1 : 1;
      return a.name < b.name ? -1 : 1;
    });
    rows.forEach(function (e) {
      lines.push("### `" + e.name + "`");
      lines.push("");
      lines.push("- **Since:** " + e.since);
      lines.push("- **Removed in:** " + e.removeIn);
      lines.push("- **Defined at:** [`" + e.file + "`](" + e.file + ")");
      if (e.kind === "alias" && e.renamedTo) {
        lines.push("- **Renamed to:** `" + e.renamedTo + "`");
      }
      if (e.message) {
        lines.push("");
        lines.push(e.message);
      }
      if (e.hint) {
        lines.push("");
        lines.push(e.hint);
      }
      lines.push("");
    });
  });

  _appendOutOfBand(lines);
  return lines.join("\n");
}

// OUT_OF_BAND_BREAKS — schema / on-disk / config-shape breaks that
// can't be expressed via `deprecate()` because there's no in-process
// runtime surface to warn from. Append as releases ship these.
//
// Each entry:
//   release:    git tag of the release that introduced the break
//   surface:    operator-visible API or on-disk artifact affected
//   summary:    one-line operator-facing description
//   migration:  multi-line markdown migration recipe
var OUT_OF_BAND_BREAKS = [
  {
    release:  "v0.9.15",
    surface:  "b.middleware.idempotencyKey.dbStore — table schema",
    summary:  "Single `v` JSON-envelope column split into discrete `fingerprint` / `status_code` / `headers` / `body` / `expires_at` columns; `headers` + `body` are sealed via `b.cryptoField.sealRow` when vault is initialized; `k` column carries the sha3-512 namespace-hash of the operator-supplied key.",
    migration: [
      "Operators with a v0.9.14 (or earlier) idempotency table on disk:",
      "",
      "```sql",
      "DROP TABLE <tableName>;   -- default: blamejs_idempotency_keys",
      "```",
      "",
      "Or pick a fresh `tableName` in v0.9.15+ `dbStore({ tableName: \"...\" })`. The init step (`init: true`, default) creates the new split-column schema. `CREATE TABLE IF NOT EXISTS` does NOT migrate column layout on an existing table, so the drop-and-recreate is required.",
      "",
      "Cached records in the existing table are not recoverable across the schema break — operators who care about replay continuity warm the new table by retrying the in-flight requests under the new dbStore.",
    ].join("\n"),
  },
];

function _appendOutOfBand(lines) {
  if (!OUT_OF_BAND_BREAKS.length) return;
  lines.push("---");
  lines.push("");
  lines.push("## Out-of-band breaking changes");
  lines.push("");
  lines.push("Listed newest-first.");
  lines.push("");
  // Semver-aware sort — `v0.9.10` must sort newer than `v0.9.9` (a naive
  // lexicographic compare would order the digit `1` before `9` and mis-
  // place them). Strip the leading `v`, split on `.`, compare each
  // numeric component. Per Codex P2 on PR #48.
  function _semverCmp(a, b) {
    var as = String(a).replace(/^v/, "").split(".").map(Number);
    var bs = String(b).replace(/^v/, "").split(".").map(Number);
    for (var i = 0; i < Math.max(as.length, bs.length); i += 1) {
      var ai = i < as.length ? as[i] : 0;
      var bi = i < bs.length ? bs[i] : 0;
      if (ai !== bi) return ai - bi;
    }
    return 0;
  }
  var sorted = OUT_OF_BAND_BREAKS.slice().sort(function (a, b) {
    return _semverCmp(b.release, a.release);   // newest first
  });
  sorted.forEach(function (e) {
    lines.push("### " + e.release + " — `" + e.surface + "`");
    lines.push("");
    lines.push(e.summary);
    lines.push("");
    lines.push(e.migration);
    lines.push("");
  });
}

fs.writeFileSync(TARGET, _build(), "utf8");
process.stdout.write("[gen-migrating] wrote " + TARGET + "\n");
