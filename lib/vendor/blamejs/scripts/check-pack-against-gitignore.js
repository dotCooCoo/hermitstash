// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// prepack guard — fail the publish if any packed path is gitignored
// (repo + global). `--ignore-scripts` on the inner pack call avoids
// re-triggering this hook.

var cp = require("node:child_process");

function _run(cmd, args, opts) {
  return cp.spawnSync(cmd, args, Object.assign({ encoding: "utf8" }, opts || {}));
}

function main() {
  // shell-form: Node 22+ rejects spawning npm.cmd directly on Windows,
  // and `shell: true` with a separate args array trips DEP0190.
  var pack = _run("npm pack --dry-run --ignore-scripts --json", [], { shell: true });
  if (pack.status !== 0) {
    process.stderr.write("[prepack-guard] npm pack --dry-run failed:\n");
    process.stderr.write(pack.stderr || "");
    process.exit(1);
  }
  var info;
  try { info = JSON.parse(pack.stdout); }
  catch (_e) {
    process.stderr.write("[prepack-guard] could not parse npm pack output\n");
    process.exit(1);
  }
  var entry = Array.isArray(info) ? info[0] : info;
  var files = (entry && entry.files) || [];
  if (files.length === 0) {
    process.stderr.write("[prepack-guard] npm pack reported zero files\n");
    process.exit(1);
  }
  // Generated artifacts intended to ship in the tarball — these are
  // gitignored on purpose (so a stray local generation doesn't pollute
  // the repo) but are listed in package.json `files` because the CI
  // workflow generates them just-in-time before publish. Skip the guard
  // for these specific paths.
  var GENERATED_ALLOWED = new Set([
    "sbom.cdx.json",
  ]);
  var paths = files.map(function (f) { return f.path; })
    .filter(function (p) { return !GENERATED_ALLOWED.has(p); });

  var check = _run("git", ["check-ignore", "--verbose", "--no-index", "--stdin"], {
    input: paths.join("\n") + "\n",
  });

  if (check.status === 1) {
    process.stdout.write(
      "[prepack-guard] ok — " + paths.length + " paths checked, none gitignored\n"
    );
    return;
  }
  if (check.status !== 0) {
    process.stderr.write("[prepack-guard] git check-ignore failed:\n");
    process.stderr.write(check.stderr || "");
    process.exit(1);
  }

  // `git check-ignore -v` reports the LAST matching gitignore line,
  // including negation (`!`) rules — but the command exits 0 even
  // when the matching line UNIGNORES the path. A `!`-prefixed pattern
  // means the file is NOT actually ignored, so it's safe to ship in
  // the tarball. Output format: `.gitignore:LINE:PATTERN<TAB>PATH`.
  var lines = (check.stdout || "").split("\n").filter(Boolean);
  var actuallyIgnored = lines.filter(function (l) {
    var m = l.match(/^[^:]+:\d+:([^\t]*)\t/);
    if (!m) return true;
    return m[1].charAt(0) !== "!";
  });
  if (actuallyIgnored.length === 0) {
    process.stdout.write(
      "[prepack-guard] ok — " + paths.length + " paths checked, " +
      lines.length + " matched a `!`-negation rule (allowed)\n"
    );
    return;
  }
  process.stderr.write("[prepack-guard] gitignored paths in tarball:\n");
  actuallyIgnored.forEach(function (l) { process.stderr.write("  " + l + "\n"); });
  process.exit(1);
}

main();
