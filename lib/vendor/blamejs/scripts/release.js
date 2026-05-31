#!/usr/bin/env node
"use strict";
/**
 * release.js — orchestrate the full release flow as a sequence of
 * idempotent subcommands. Each subcommand performs ONE phase, prints
 * what it did, and exits with a code that's safe to script against
 * in a CI runner or operator's terminal.
 *
 * Usage:
 *   node scripts/release.js prepare    # bump + regen CHANGELOG + api-snapshot + static gates
 *   node scripts/release.js regen      # re-regen CHANGELOG + api-snapshot (after release-notes edits)
 *   node scripts/release.js smoke      # SMOKE_PARALLEL=64 + (optional) wiki e2e
 *   node scripts/release.js commit     # release branch + signed commit
 *   node scripts/release.js push       # gitleaks + push + open PR
 *   node scripts/release.js watch      # gh pr checks --watch + flag Codex threads
 *   node scripts/release.js merge      # squash-merge if CLEAN + zero unresolved threads
 *   node scripts/release.js tag        # signed tag + push tag + verify
 *   node scripts/release.js publish    # watch npm-publish + release-container
 *   node scripts/release.js all        # all eight in sequence
 *
 *   node scripts/release.js help       # this banner
 *   node scripts/release.js status     # what phase the current branch is in
 *
 * Pre-conditions:
 *   - The release-notes JSON `release-notes/v<next>.json` MUST already
 *     exist before `prepare` runs. The script refuses with a template
 *     stub printed to stdout otherwise — the headline / summary /
 *     sections require human judgment and don't auto-generate from a
 *     diff.
 *   - Git signing config (SSH + allowed_signers + commit/tag.gpgsign)
 *     must be in place. See CLAUDE.md "Release workflow" — one-time
 *     signing setup.
 *
 * The judgment-requiring parts stay manual:
 *   - Writing `release-notes/v<next>.json` content.
 *   - Reviewing Codex P1/P2 findings (watch flags them + stops; the
 *     operator writes the fix + re-runs watch).
 *   - Choosing minor vs patch bump (default: patch per CLAUDE.md;
 *     override via `--minor` on prepare).
 */

var fs = require("node:fs");
var path = require("node:path");
var childProcess = require("node:child_process");

var ROOT = path.resolve(__dirname, "..");

// ---- Helpers -------------------------------------------------------------

// Windows resolves `npm` / `npx` as `npm.cmd` / `npx.cmd` shims, which
// child_process.spawn can only invoke through a shell. Everything else
// in the release-flow toolchain (`gh`, `git`, `docker`, `node`) is a
// native exe that spawns directly without shell — keeping shell off
// avoids the DEP0190 deprecation + the implicit arg-quoting risk.
function _needsShell(cmd) {
  if (process.platform !== "win32") return false;
  return cmd === "npm" || cmd === "npx";
}

function _readPackageVersion() {
  var pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  return pkg.version;
}

function _writePackageVersion(next) {
  var pkgPath = path.join(ROOT, "package.json");
  var content = fs.readFileSync(pkgPath, "utf8");
  var updated = content.replace(/"version":\s*"[^"]+"/, '"version": "' + next + '"');
  if (updated === content) {
    throw new Error("release: failed to rewrite package.json version line");
  }
  fs.writeFileSync(pkgPath, updated);
}

function _bumpPatch(version) {
  var parts = version.split(".").map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  return parts[0] + "." + parts[1] + "." + (parts[2] + 1);
}

function _bumpMinor(version) {
  var parts = version.split(".").map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  return parts[0] + "." + (parts[1] + 1) + ".0";
}

// Quote a single argument for a Windows cmd.exe command line. Tokens
// made only of safe characters pass through unquoted; anything else is
// double-quoted with embedded quotes doubled.
function _quoteWinArg(a) {
  a = String(a);
  if (/^[A-Za-z0-9_@.\-/:=]+$/.test(a)) return a;
  return '"' + a.replace(/"/g, '""') + '"';
}

function _run(cmd, args, opts) {
  opts = opts || {};
  args = args || [];
  var spawnCmd = cmd;
  var spawnArgs = args;
  var useShell = false;
  if (_needsShell(cmd)) {
    // Windows resolves npm / npx through .cmd shims that can only be
    // launched via a shell (the CVE-2024-27980 mitigation refuses to
    // spawn .cmd files without one). Node 26's DEP0190 deprecates
    // pairing an args ARRAY with shell:true because the args would be
    // concatenated onto the command line without escaping — a quoting /
    // injection hazard. Build a single, explicitly-quoted command
    // string and pass NO args array, which is the supported shape.
    spawnCmd = [cmd].concat(args.map(_quoteWinArg)).join(" ");
    spawnArgs = undefined;
    useShell = true;
  }
  var rv = childProcess.spawnSync(spawnCmd, spawnArgs, {
    cwd:    opts.cwd   || ROOT,
    stdio:  opts.stdio || "inherit",
    env:    Object.assign({}, process.env, opts.env || {}),
    shell:  useShell,
  });
  if (rv.status !== 0 && !opts.allowFail) {
    throw new Error("release: " + cmd + " " + args.join(" ") +
                    " failed with status " + rv.status);
  }
  return rv;
}

function _capture(cmd, args, opts) {
  opts = opts || {};
  var rv = childProcess.spawnSync(cmd, args, {
    cwd:   opts.cwd || ROOT,
    stdio: ["ignore", "pipe", "pipe"],
    env:   Object.assign({}, process.env, opts.env || {}),
    shell: process.platform === "win32",
  });
  return {
    status: rv.status,
    stdout: (rv.stdout || "").toString().trim(),
    stderr: (rv.stderr || "").toString().trim(),
  };
}

function _gitClean() {
  var rv = _capture("git", ["status", "--porcelain"]);
  return rv.stdout === "";
}

function _gitBranch() {
  return _capture("git", ["rev-parse", "--abbrev-ref", "HEAD"]).stdout;
}

function _gitOnMain() {
  return _gitBranch() === "main";
}

function _gitOnRelease() {
  return /^release\/v\d+\.\d+\.\d+$/.test(_gitBranch());
}

function _releaseBranchFor(version) {
  return "release/v" + version;
}

function _releaseNotesPath(version) {
  return path.join(ROOT, "release-notes", "v" + version + ".json");
}

function _ensureReleaseNotes(version) {
  var p = _releaseNotesPath(version);
  if (!fs.existsSync(p)) {
    var stub = {
      $schema:  "../scripts/release-notes-schema.json",
      version:  version,
      date:     new Date().toISOString().slice(0, 10),
      headline: "<one-line operator-facing summary — start with a capital letter or `backtick>",
      summary:  "<one-paragraph why-it-matters>",
      sections: [
        {
          heading: "Added",
          items: [
            { title: "<short title>", body: "<one-paragraph body — ends in sentence punctuation>" },
          ],
        },
      ],
      references: [],
    };
    console.error("");
    console.error("release: missing " + p);
    console.error("");
    console.error("Create that file before re-running. Stub template:");
    console.error("");
    console.error(JSON.stringify(stub, null, 2));
    console.error("");
    process.exit(2);
  }
  return p;
}

function _section(title) {
  console.log("\n=== " + title + " ===");
}

function _ok(msg) {
  console.log("ok: " + msg);
}

// Shared artifact-regeneration helper. Called by `prepare` after the
// version bump, and standalone via `regen` when the operator edits
// release-notes mid-flow (e.g. addressing a Codex P1/P2 finding that
// belongs in the operator-facing release notes). Idempotent — running
// it twice with no edits in between is a no-op.
function _regenArtifacts(opts) {
  opts = opts || {};
  if (opts.rollupOnMinor) {
    _run("node", ["scripts/consolidate-release-notes.js", "--prune"]);
    _ok("prior minor's release-notes rolled up");
  }
  _run("node", ["scripts/generate-changelog-entry.js", "--rebuild"]);
  _run("node", ["scripts/refresh-api-snapshot.js"]);
  _run("node", ["scripts/check-api-snapshot.js"]);
  _run("node", ["scripts/check-changelog-extract.js"]);
  _ok("CHANGELOG + api-snapshot regenerated");
}

// Verify HEAD's commit signature using two independent code paths:
//   1. `git verify-commit HEAD` — exits 0 on Good signature; this is
//      the canonical truth signal (matches what GitHub's
//      required_signatures ruleset checks).
//   2. `git log -1 --pretty=%h %G? %GS` — capture the sha + signature
//      letter + signer email for human-readable confirmation.
// The script previously relied solely on (2), but the `%G?` token's
// `?` character can be eaten on some platforms when spawned through
// shell-resolution layers; (1) is a reliable boolean even when (2)
// returns empty stdout.
function _verifyCommitSignature(label) {
  var verifyRv = _capture("git", ["verify-commit", "HEAD"]);
  if (verifyRv.status !== 0) {
    var hint = "release: " + label + " commit signature is not Good — " +
               "check SSH signing setup (commit.gpgsign=true + gpg.format=ssh + " +
               "~/.ssh/allowed_signers populated).";
    if (verifyRv.stderr) hint += "\n" + verifyRv.stderr;
    throw new Error(hint);
  }
  var sig = _capture("git", ["log", "-1", "--pretty=%h %G? %GS"]);
  console.log("signature: " + (sig.stdout || "(captured empty — verify-commit reports Good)"));
  _ok(label + " commit signature verified");
}

// ---- Subcommands ---------------------------------------------------------

function cmdPrepare(opts) {
  _section("prepare");
  if (!_gitOnMain()) {
    throw new Error("release: prepare must run on main (currently on " + _gitBranch() + ")");
  }
  if (!_gitClean()) {
    throw new Error("release: prepare requires a clean working tree");
  }

  var current = _readPackageVersion();
  var next = opts.minor ? _bumpMinor(current) : _bumpPatch(current);
  console.log("current version: " + current);
  console.log("next version:    " + next + " (" + (opts.minor ? "minor" : "patch") + ")");

  _ensureReleaseNotes(next);

  _writePackageVersion(next);
  _ok("bumped package.json → " + next);

  _section("regen artifacts");
  // Minor bump: consolidate the prior minor's per-patch release-notes
  // files into a single rollup so smoke's release-notes rollup gate
  // stays green. No-op on patch bumps.
  var minorRotated = current.split(".")[1] !== next.split(".")[1];
  _regenArtifacts({ rollupOnMinor: minorRotated });

  _section("static gates");
  _run("npx", ["--yes", "eslint@latest", "--max-warnings", "0", "."]);
  _run("node", ["test/layer-0-primitives/codebase-patterns.test.js"]);
  _run("node", ["scripts/validate-source-comment-blocks.js"]);
  _ok("eslint + codebase-patterns + source-comment-blocks clean");

  _section("supply-chain currency");
  // A stale SHA-pinned GitHub Action or vendored bundle becomes a
  // release blocker HERE — with a ready-to-paste pin line in the
  // actions report — instead of an after-the-fact Dependabot PR.
  // Each script treats only an actually-newer upstream version as a
  // failure; transient registry / API errors stay advisory (exit 0)
  // so a flaky network response doesn't block the cut.
  _run("node", ["scripts/check-actions-currency.js"]);
  _run("node", ["scripts/check-vendor-currency.js"]);
  _ok("github actions + vendored bundles current");

  console.log("\nnext: node scripts/release.js smoke");
}

function cmdRegen() {
  _section("regen");
  // Operators edit release-notes/v<next>.json mid-flow (e.g.
  // addressing a Codex finding that belongs in the operator-facing
  // notes, or fixing a leak-vocabulary refusal that the changelog
  // emitter raised). This subcommand re-runs the artifact pipeline
  // without re-bumping the version. Safe to run from any branch.
  var next = _readPackageVersion();
  _ensureReleaseNotes(next);
  _regenArtifacts();
  console.log("\nnext: re-run the phase you were on (commit / push / watch / ...)");
}

function cmdSmoke() {
  _section("smoke");
  _run("node", ["test/smoke.js"], { env: { SMOKE_PARALLEL: "64" } });
  _ok("framework smoke clean");

  // wiki e2e — only if examples/wiki was touched in the diff since main.
  var diffRv = _capture("git", ["diff", "--name-only", "origin/main..HEAD"]);
  var changed = diffRv.stdout.split(/\r?\n/);
  var wikiTouched = changed.some(function (p) { return p.indexOf("examples/wiki") === 0; });
  if (!wikiTouched) {
    var localDiffRv = _capture("git", ["diff", "--name-only"]);
    wikiTouched = localDiffRv.stdout.split(/\r?\n/).some(function (p) {
      return p.indexOf("examples/wiki") === 0;
    });
  }
  if (wikiTouched) {
    _section("wiki e2e");
    var wikiDir = path.join(ROOT, "examples", "wiki");
    try { fs.rmSync(path.join(wikiDir, "data"),     { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(path.join(wikiDir, "data-e2e"), { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    _run("node", ["test/e2e.js"], { cwd: wikiDir, env: { SMOKE_PARALLEL: "64" } });
    _ok("wiki e2e clean");
  } else {
    _ok("wiki untouched — skipping e2e");
  }

  console.log("\nnext: node scripts/release.js commit");
}

function cmdCommit() {
  _section("commit");
  var next = _readPackageVersion();
  var branch = _releaseBranchFor(next);
  var current = _gitBranch();

  // Resumable: if a previous `commit` invocation failed AFTER the
  // `git checkout -b` (e.g. signature verification, write-protected
  // file, hook failure), the branch already exists. Switch to it
  // instead of refusing. The remaining checks (the commit itself,
  // signature verify) are idempotent.
  if (current === branch) {
    _ok("already on " + branch + " (resume mode)");
  } else if (current === "main") {
    var branchExists = _capture("git", ["rev-parse", "--verify", "--quiet", branch]).status === 0;
    if (branchExists) {
      _run("git", ["checkout", branch]);
      _ok("checked out existing " + branch + " (resume mode)");
    } else {
      _run("git", ["checkout", "-b", branch]);
      _ok("created " + branch);
    }
  } else {
    throw new Error("release: commit must run on main or " + branch +
                    " (currently on " + current + ")");
  }

  // If HEAD already carries a commit for this release (re-run after
  // signature failure was resolved out-of-band, or just an over-eager
  // re-invocation), skip the second commit. Verify the existing
  // signature instead.
  var headSubject = _capture("git", ["log", "-1", "--pretty=%s"]).stdout;
  if (headSubject.indexOf(next + " — ") === 0) {
    _ok("HEAD already carries a " + next + " release commit (resume mode)");
    _verifyCommitSignature("existing");
    console.log("\nnext: node scripts/release.js push");
    return;
  }

  // Compose commit body from the release-notes JSON. Operators can
  // amend post-commit; the auto-generated body is meant as a sensible
  // default that mirrors the CHANGELOG entry shape.
  var rn = JSON.parse(fs.readFileSync(_releaseNotesPath(next), "utf8"));
  var lines = [next + " — " + rn.headline, "", rn.summary];
  if (Array.isArray(rn.sections)) {
    rn.sections.forEach(function (s) {
      if (!Array.isArray(s.items) || s.items.length === 0) return;
      lines.push("", s.heading + ":");
      s.items.forEach(function (it) {
        lines.push("  - " + it.title);
      });
    });
  }
  var msgPath = path.join(ROOT, ".scratch", "release-commit-msg.txt");
  try { fs.mkdirSync(path.dirname(msgPath), { recursive: true }); } catch (_e) { /* ignore */ }
  fs.writeFileSync(msgPath, lines.join("\n") + "\n");

  _run("git", ["add", "-A"]);
  _run("git", ["commit", "-F", msgPath]);
  _ok("signed commit");

  _verifyCommitSignature("new");

  console.log("\nnext: node scripts/release.js push");
}

function cmdPush() {
  _section("push");
  if (!_gitOnRelease()) {
    throw new Error("release: push must run on a release/vX.Y.Z branch");
  }
  var next = _readPackageVersion();

  _section("gitleaks");
  // Docker bind-mount path: Windows host paths look like
  // `C:\Users\Robert\Dropbox (Personal)\...`; Docker Desktop accepts
  // them as `//c/Users/Robert/Dropbox (Personal)/...` (double leading
  // slash + lowercased drive letter without colon — Git Bash's
  // `$(pwd)` form). The colon in `C:` confuses Docker's `-v src:dst`
  // splitter, so transform here.
  var mount;
  if (process.platform === "win32") {
    var posixified = ROOT.replace(/\\/g, "/");
    mount = "//" + posixified.charAt(0).toLowerCase() + posixified.slice(2);   // C:/x → //c/x
  } else {
    mount = ROOT;
  }
  _run("docker", [
    "run", "--rm",
    "-v", mount + ":/repo",
    "-w", "//repo",
    "zricethezav/gitleaks:latest",
    "git", "--config=.gitleaks.toml", "--redact", "--exit-code=1",
  ]);
  _ok("gitleaks clean");

  _section("push branch");
  _run("git", ["push", "-u", "origin", _releaseBranchFor(next)]);
  _ok("pushed " + _releaseBranchFor(next));

  _section("open PR");
  var rn = JSON.parse(fs.readFileSync(_releaseNotesPath(next), "utf8"));
  var title = next + " — " + rn.headline;
  var summaryLines = ["## Summary", "", rn.summary, "", "## Test plan", ""];
  summaryLines.push("- [x] `node test/smoke.js` — passes");
  summaryLines.push("- [x] `node test/layer-0-primitives/codebase-patterns.test.js` — clean");
  summaryLines.push("- [x] `gitleaks` — no leaks");
  summaryLines.push("- [ ] CI green");
  _run("gh", ["pr", "create",
              "--base", "main",
              "--head", _releaseBranchFor(next),
              "--title", title,
              "--body",  summaryLines.join("\n")]);
  _ok("PR opened");

  console.log("\nnext: node scripts/release.js watch");
}

function cmdWatch() {
  _section("watch");
  var prNum = _capture("gh", ["pr", "list",
                              "--author", "@me",
                              "--state",  "open",
                              "--head",   _releaseBranchFor(_readPackageVersion()),
                              "--json",   "number",
                              "--jq",     ".[0].number"]).stdout;
  if (!prNum) {
    throw new Error("release: no open PR for branch " + _releaseBranchFor(_readPackageVersion()));
  }
  console.log("PR #" + prNum);

  _run("gh", ["pr", "checks", prNum, "--watch"], { allowFail: true });

  var threadRv = _capture("gh", ["api", "graphql",
                                  "-f", "query=query { repository(owner:\"blamejs\",name:\"blamejs\") { pullRequest(number:" + prNum +
                                       ") { reviewThreads(first:50) { nodes { isResolved comments(first:1) { nodes { author{login} body } } } } } } }",
                                  "--jq", ".data.repository.pullRequest.reviewThreads.nodes | map(select(.isResolved==false))"]);
  var unresolved = JSON.parse(threadRv.stdout || "[]");
  if (unresolved.length > 0) {
    console.log("\nunresolved review threads (" + unresolved.length + "):");
    unresolved.forEach(function (t) {
      var c = t.comments && t.comments.nodes && t.comments.nodes[0];
      if (c) {
        console.log("  - by " + c.author.login + ": " + c.body.split("\n")[0]);
      }
    });
    console.log("");
    console.log("Resolve threads + push fixes, then re-run: node scripts/release.js watch");
    process.exit(3);
  }
  _ok("zero unresolved threads");

  console.log("\nnext: node scripts/release.js merge");
}

function cmdMerge() {
  _section("merge");
  var next = _readPackageVersion();
  var branch = _releaseBranchFor(next);
  var prNum = _capture("gh", ["pr", "list", "--head", branch, "--state", "open",
                              "--json", "number", "--jq", ".[0].number"]).stdout;
  if (!prNum) {
    throw new Error("release: no open PR for " + branch);
  }
  var state = JSON.parse(_capture("gh", ["pr", "view", prNum,
    "--json", "mergeStateStatus,mergeable"]).stdout || "{}");
  if (state.mergeStateStatus !== "CLEAN" || state.mergeable !== "MERGEABLE") {
    throw new Error("release: PR #" + prNum + " not mergeable (state=" +
                    state.mergeStateStatus + " mergeable=" + state.mergeable + ")");
  }
  // Re-check unresolved review threads RIGHT BEFORE the merge call.
  // `watch` enforces zero unresolved at watch time, but a reviewer
  // can open a new thread between watch + merge, or main-protection
  // may not enforce `require_review_thread_resolution` on every repo
  // — the merge gate stays robust either way.
  var threadRv = _capture("gh", ["api", "graphql",
                                  "-f", "query=query { repository(owner:\"blamejs\",name:\"blamejs\") { pullRequest(number:" + prNum +
                                       ") { reviewThreads(first:50) { nodes { isResolved comments(first:1) { nodes { author{login} body } } } } } } }",
                                  "--jq", ".data.repository.pullRequest.reviewThreads.nodes | map(select(.isResolved==false))"]);
  var unresolved = JSON.parse(threadRv.stdout || "[]");
  if (unresolved.length > 0) {
    console.log("\nunresolved review threads opened since watch (" + unresolved.length + "):");
    unresolved.forEach(function (t) {
      var c = t.comments && t.comments.nodes && t.comments.nodes[0];
      if (c) console.log("  - by " + c.author.login + ": " + c.body.split("\n")[0]);
    });
    throw new Error("release: refusing to merge PR #" + prNum + " — unresolved review threads");
  }
  _run("gh", ["pr", "merge", prNum, "--squash", "--delete-branch"]);
  _ok("PR #" + prNum + " squash-merged");

  _run("git", ["checkout", "main"]);
  _run("git", ["pull", "origin", "main"]);

  console.log("\nnext: node scripts/release.js tag");
}

function cmdTag() {
  _section("tag");
  if (!_gitOnMain()) {
    throw new Error("release: tag must run on main (post-merge)");
  }
  var next = _readPackageVersion();
  var tag = "v" + next;

  // Refuse if the tag already exists. The release-tags ruleset
  // refuses tag overwrites server-side, but a clearer client-side
  // error makes the surprise smaller.
  var existing = _capture("git", ["tag", "-l", tag]).stdout;
  if (existing === tag) {
    throw new Error("release: tag " + tag + " already exists locally");
  }
  _run("git", ["tag", "-s", tag, "-m", tag]);
  _run("git", ["push", "origin", tag]);
  _ok("tagged + pushed " + tag);

  var verify = _capture("git", ["tag", "-v", tag]);
  if (verify.stderr.indexOf("Good") === -1 && verify.stdout.indexOf("Good") === -1) {
    console.error("warning: `git tag -v " + tag + "` did not report a Good signature:");
    console.error(verify.stderr || verify.stdout);
  } else {
    _ok("tag signature: Good");
  }

  console.log("\nnext: node scripts/release.js publish");
}

function cmdPublish() {
  _section("publish");
  var next = _readPackageVersion();

  _section("npm-publish workflow");
  var npmRunId = _capture("gh", ["run", "list",
                                  "--workflow=npm-publish.yml",
                                  "--limit", "1",
                                  "--json", "databaseId",
                                  "--jq",   ".[0].databaseId"]).stdout;
  if (npmRunId) {
    _run("gh", ["run", "watch", npmRunId, "--exit-status"], { allowFail: true });
  } else {
    console.log("no npm-publish run found (workflow may not be configured)");
  }

  _section("release-container workflow");
  var containerRunId = _capture("gh", ["run", "list",
                                        "--workflow=release-container.yml",
                                        "--limit", "1",
                                        "--json", "databaseId",
                                        "--jq",   ".[0].databaseId"]).stdout;
  if (containerRunId) {
    _run("gh", ["run", "watch", containerRunId, "--exit-status"], { allowFail: true });
  } else {
    console.log("no release-container run found (workflow may not be configured)");
  }

  _section("verify");
  var npmVersion = _capture("npm", ["view", "@blamejs/core", "version"]).stdout;
  console.log("npm @blamejs/core: " + (npmVersion || "(unable to query)") +
              "  (expected: " + next + ")");
  if (npmVersion && npmVersion !== next) {
    console.error("warning: npm version doesn't match expected — workflow may still be in flight");
  } else if (npmVersion === next) {
    _ok("npm matches " + next);
  }
}

function cmdAll(opts) {
  cmdPrepare(opts);
  cmdSmoke();
  cmdCommit();
  cmdPush();
  cmdWatch();
  cmdMerge();
  cmdTag();
  cmdPublish();
}

function cmdStatus() {
  _section("status");
  console.log("branch:           " + _gitBranch());
  console.log("clean:            " + _gitClean());
  console.log("package version:  " + _readPackageVersion());
  console.log("release-notes:    " + (fs.existsSync(_releaseNotesPath(_readPackageVersion())) ? "present" : "missing"));
  var prNum = _capture("gh", ["pr", "list",
                              "--author", "@me",
                              "--head",   _releaseBranchFor(_readPackageVersion()),
                              "--state",  "open",
                              "--json",   "number,mergeStateStatus,mergeable",
                              "--jq",     ".[0]"]).stdout;
  if (prNum) {
    console.log("open PR:          " + prNum);
  } else {
    console.log("open PR:          (none)");
  }
}

function cmdHelp() {
  console.log("release.js — orchestrated release flow");
  console.log("");
  console.log("Usage:");
  console.log("  node scripts/release.js prepare [--minor]   # bump + regen + static gates");
  console.log("  node scripts/release.js regen               # re-regen artifacts after release-notes edits");
  console.log("  node scripts/release.js smoke               # framework + wiki e2e if needed");
  console.log("  node scripts/release.js commit              # release branch + signed commit");
  console.log("  node scripts/release.js push                # gitleaks + push + open PR");
  console.log("  node scripts/release.js watch               # CI watch + flag Codex threads");
  console.log("  node scripts/release.js merge               # squash-merge if CLEAN");
  console.log("  node scripts/release.js tag                 # signed tag + push tag");
  console.log("  node scripts/release.js publish             # watch publish workflows");
  console.log("  node scripts/release.js all [--minor]       # all eight in sequence");
  console.log("  node scripts/release.js status              # current branch + version state");
  console.log("  node scripts/release.js help                # this banner");
}

// ---- Dispatch ------------------------------------------------------------

var sub = process.argv[2] || "help";
var args = process.argv.slice(3);
var opts = {
  minor: args.indexOf("--minor") !== -1,
};

try {
  switch (sub) {
    case "prepare": cmdPrepare(opts); break;
    case "regen":   cmdRegen();       break;
    case "smoke":   cmdSmoke();       break;
    case "commit":  cmdCommit();      break;
    case "push":    cmdPush();        break;
    case "watch":   cmdWatch();       break;
    case "merge":   cmdMerge();       break;
    case "tag":     cmdTag();         break;
    case "publish": cmdPublish();     break;
    case "all":     cmdAll(opts);     break;
    case "status":  cmdStatus();      break;
    case "help":
    case "--help":
    case "-h":      cmdHelp();        break;
    default:
      console.error("release: unknown subcommand '" + sub + "'");
      cmdHelp();
      process.exit(1);
  }
} catch (e) {
  console.error("\nrelease: FAIL — " + (e.message || e));
  process.exit(1);
}
