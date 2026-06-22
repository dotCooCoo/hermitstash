#!/usr/bin/env node
/**
 * release.js — staged release runner.
 *
 * One orchestrator, one subcommand per stage. Cutting a release walks the
 * stages in order; each is idempotent and re-runnable, so a failed cut
 * resumes from the stage that failed rather than from the top.
 *
 * HermitStash ships from a private repo into a public mirror, so the flow is
 * not a single-repo tag-and-publish: changes land in hermitstash-private, are
 * mirrored verbatim into ../hermitstash, and BOTH repos carry the signed tag.
 * The public tag push is what triggers the Docker build + the automatic
 * GitHub Release. The runner encodes that two-repo shape explicitly.
 *
 *   status     Show versions (constants.js / package.json / release-notes),
 *              branch + clean state of both repos, latest tags, in-flight
 *              Docker run. Read-only.
 *   bump       Bump the patch (or --minor) version in lib/constants.js AND
 *              package.json together, and scaffold release-notes/vX.Y.Z.json
 *              if it does not exist yet. Local edits only — reversible.
 *   changelog  Rebuild CHANGELOG.md from release-notes/ (a derived artifact).
 *              Run after filling the release-notes entry.
 *   preflight  Read-only gate: version agreement across the three files, the
 *              changelog-drift / rollup / extract / pattern gates, and the two
 *              currency gates (actions-currency + vendor-currency). It does NOT
 *              rebuild CHANGELOG — it reports drift so `changelog` is a visible
 *              step, never a hidden side effect.
 *   e2e        Full end-to-end suite from ../hermitstash-sync.
 *   commit     Signed commit of the release on private main + push.
 *   sync       Mirror tracked files into ../hermitstash, then signed commit
 *              + push on public main.
 *   tag        Signed vX.Y.Z tag on BOTH repos + push. The public push starts
 *              the Docker build + the automatic GitHub Release.
 *   watch      Surface the CI URLs, follow the tag's public Docker run to
 *              completion, confirm the GitHub Release was created.
 *   trivy      Point at the tag's Trivy visibility scan to triage for the
 *              next patch.
 *   all        changelog → preflight → e2e → commit → sync → tag → watch → trivy.
 *
 * Granular currency gates (also folded into preflight):
 *   actions    actions-currency only — every plain `uses: owner/repo@<ref>` in
 *              .github/workflows/ must be the full 40-hex commit SHA of the
 *              action's latest release, carrying a `# vX.Y.Z` comment. A tag
 *              pin (@v6), a branch pin (@master), or a SHA that no longer
 *              matches the latest release is stale and FAILS the cut with a
 *              paste-ready `owner/repo@<sha> # vX.Y.Z` line + every file:line.
 *              Reusable workflows (owner/repo/.github/workflows/x.yml@ref) are
 *              the exception: they must stay TAG-pinned (the SLSA generator
 *              refuses a SHA), so the gate checks the tag is current instead.
 *   vendor     vendor-currency only — vendored blamejs must be at the latest
 *              github.com/blamejs/blamejs release.
 *   patterns   patterns-currency ADVISORY — compares HS's codebase-patterns lint
 *              gate against the vendored blamejs gate and lists detector classes
 *              blamejs has that HS hasn't adopted (= candidate new checks /
 *              features to implement). Surfaces drift; never blocks the cut.
 *
 * Flags:
 *   --minor    bump minor instead of patch (bump / all)
 *   --yes      actually execute the mutating stages (commit/sync/tag/all);
 *              without it those stages PREVIEW the commands they would run
 *   --dry-run  force preview even with --yes (also skips the heavy e2e run
 *              and the changelog rebuild)
 *
 * Network: action + blamejs release resolution and the Docker-run watch use
 * the `gh` CLI (GITHUB_TOKEN in CI for rate limits). A gate that cannot reach
 * gh fails rather than passing — a cut must not slip a stale pin because the
 * check could not run.
 *
 * Exit codes: 0 ok · 1 a gate/stage failed · 2 release-notes missing (template
 * written) · 3 versions disagree across the three files.
 */
"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var cp = require("node:child_process");

var REPO = path.join(__dirname, "..");
var PUBLIC_REPO = path.join(REPO, "..", "hermitstash");
var SYNC_REPO = path.join(REPO, "..", "hermitstash-sync");
var WORKFLOWS_DIR = path.join(REPO, ".github", "workflows");
var MANIFEST = path.join(REPO, "lib", "vendor", "MANIFEST.json");
var CONSTANTS_JS = path.join(REPO, "lib", "constants.js");
var PACKAGE_JSON = path.join(REPO, "package.json");
var RELEASE_NOTES_DIR = path.join(REPO, "release-notes");
var HS_PATTERNS_GATE = path.join(REPO, "tests", "lint", "codebase-patterns.test.js");
var BJ_PATTERNS_GATE = path.join(REPO, "lib", "vendor", "blamejs", "test", "layer-0-primitives", "codebase-patterns.test.js");

var PRIVATE_SLUG = "dotCooCoo/hermitstash-private";
var PUBLIC_SLUG = "dotCooCoo/hermitstash";

var RED = "\x1b[31m", GREEN = "\x1b[32m", YELLOW = "\x1b[33m", CYAN = "\x1b[36m", DIM = "\x1b[2m", BOLD = "\x1b[1m", RESET = "\x1b[0m";
// No ANSI when piped / NO_COLOR — keeps CI logs + GitHub step summaries clean.
var USE_COLOR = !process.env.NO_COLOR && !!process.stdout.isTTY;
function paint(code, s) { return USE_COLOR ? code + s + RESET : s; }
function red(s) { return paint(RED, s); }
function green(s) { return paint(GREEN, s); }
function yellow(s) { return paint(YELLOW, s); }
function cyan(s) { return paint(CYAN, s); }
function dim(s) { return paint(DIM, s); }
function bold(s) { return paint(BOLD, s); }

var SHA40_RE = /^[0-9a-f]{40}$/i;
var SEMVER_RE = /^\d+\.\d+\.\d+$/;

var FLAGS = { minor: false, yes: false, dryRun: false };
function willExecute() { return FLAGS.yes && !FLAGS.dryRun; }

// ---- shell helpers ------------------------------------------------------

// Strip OPENSSL_CONF — a stray value breaks the sync E2E + the sync script.
function cleanEnv() {
  var e = Object.assign({}, process.env);
  delete e.OPENSSL_CONF;
  return e;
}

// Cross-platform synchronous sleep (poll loops).
function sleepMs(ms) {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch (_e) { /* best-effort */ }
}

// Capture stdout (null on any non-zero exit), no inherited stderr.
function capture(file, args, opts) {
  try {
    return cp.execFileSync(file, args, Object.assign(
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }, opts)).trim();
  } catch (_e) { return null; }
}

// Run with inherited stdio; throws on non-zero so the caller can stop the cut.
function run(file, args, opts) {
  return cp.execFileSync(file, args, Object.assign({ stdio: "inherit" }, opts));
}

// Mutating command for an ACTION stage: executes only when --yes (and not
// --dry-run); otherwise prints what it WOULD do so a cut can be rehearsed.
function act(file, args, opts) {
  var pretty = file + " " + args.join(" ");
  if (!willExecute()) { console.log(dim("    would run: " + pretty)); return null; }
  console.log(dim("    + " + pretty));
  return cp.execFileSync(file, args, Object.assign({ stdio: "inherit" }, opts));
}

function gitCap(dir, args) { return capture("git", ["-C", dir].concat(args)); }
function gitAct(dir, args, opts) { return act("git", ["-C", dir].concat(args), opts); }
function gitClean(dir) { return !gitCap(dir, ["status", "--porcelain"]); }
function gitBranch(dir) { return gitCap(dir, ["rev-parse", "--abbrev-ref", "HEAD"]); }

function ghAvailable() {
  try { cp.execFileSync("gh", ["--version"], { stdio: "ignore" }); return true; }
  catch (_e) { return false; }
}
function ghApi(apiPath, jq) {
  var args = ["api", apiPath];
  if (jq) args.push("--jq", jq);
  return capture("gh", args);
}
function bashAvailable() {
  try { cp.execFileSync("bash", ["--version"], { stdio: "ignore" }); return true; }
  catch (_e) { return false; }
}

// ---- semver -------------------------------------------------------------

// Compare X.Y.Z (ignoring any -prerelease / +build suffix). -1 / 0 / 1.
function semverCmp(a, b) {
  // Fail loud on a null/undefined input (e.g. a failed GitHub-API tag resolve):
  // without this it coerces to "null" → NaN → 0, falsely reporting a stale pin
  // as current and slipping it past the currency gate. A non-semver string
  // (e.g. a SHA ref) is still compared leniently, as before.
  if (a == null || b == null) {
    throw new Error("semverCmp: null/undefined version (" + JSON.stringify(a) + ", " + JSON.stringify(b) + ")");
  }
  var pa = String(a).replace(/^v/, "").split(/[-+]/)[0].split(".").map(Number);
  var pb = String(b).replace(/^v/, "").split(/[-+]/)[0].split(".").map(Number);
  for (var i = 0; i < 3; i++) {
    var x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
function refMajor(ref) { var m = /^v?(\d+)/.exec(String(ref)); return m ? Number(m[1]) : null; }
function commentSemver(comment) { var m = /v?(\d+\.\d+\.\d+)/.exec(comment || ""); return m ? m[1] : null; }

// ---- version helpers ----------------------------------------------------

function pkgVersion() { return JSON.parse(fs.readFileSync(PACKAGE_JSON, "utf8")).version; }

function constantsVersion() {
  // Anchor on a line that is exactly `version:` — not cssVersion/jsVersion/etc.
  var m = /^\s*version:\s*["']([\d.]+)["']/m.exec(fs.readFileSync(CONSTANTS_JS, "utf8"));
  return m ? m[1] : null;
}

function releaseNotesPath(v) { return path.join(RELEASE_NOTES_DIR, "v" + v + ".json"); }
function releaseNotes(v) {
  var p = releaseNotesPath(v);
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : null;
}

function bumpVersion(cur, minor) {
  var p = cur.split(".").map(Number);
  if (minor) { p[1]++; p[2] = 0; } else { p[2]++; }
  return p.join(".");
}

function commitSubject(v, rn) {
  return rn && rn.headline ? ("release: v" + v + " — " + rn.headline) : ("release: v" + v);
}
function tagMessage(v, rn) {
  return rn && rn.headline ? ("v" + v + " — " + rn.headline) : ("v" + v);
}

// HEAD of `dir` is the release commit for v? Subject match, with a structural
// fallback (committed package.json version == v) so a headline-casing or
// amend mismatch does not abort a cut whose release commit is genuinely there.
function headIsReleaseCommit(dir, subject, v) {
  if (gitCap(dir, ["log", "-1", "--pretty=%s"]) === subject) return true;
  if (v) {
    var src = gitCap(dir, ["show", "HEAD:package.json"]);
    if (src) { try { if (JSON.parse(src).version === v) return true; } catch (_e) { /* not JSON */ } }
  }
  return false;
}

// Verify the three version sources agree; print a table. Returns true/false.
function versionConsistency() {
  var pv = pkgVersion(), cv = constantsVersion();
  var rn = releaseNotes(pv), rnV = rn && rn.version;
  var rnExists = fs.existsSync(releaseNotesPath(pv));
  var ok = pv && cv === pv && rnExists && rnV === pv;
  function mark(val) { return val === pv ? green(val) : red(val || "—"); }
  console.log("  package.json        " + mark(pv));
  console.log("  lib/constants.js    " + mark(cv));
  console.log("  release-notes       " + (rnExists ? mark(rnV) : red("missing v" + pv + ".json")));
  return ok;
}

// ---- workflow parsing + action resolution -------------------------------

// A reusable workflow (owner/repo/.github/workflows/x.yml@ref) must stay
// tag-pinned — the SLSA generator refuses a commit-SHA reference.
function isReusableWorkflow(fullPath) { return /\/\.github\/workflows\/.+\.ya?ml$/.test(fullPath); }

function parseWorkflowUses() {
  var uses = [];
  if (!fs.existsSync(WORKFLOWS_DIR)) return uses;
  var files = fs.readdirSync(WORKFLOWS_DIR).filter(function (f) { return /\.ya?ml$/.test(f); });
  var re = /^\s*-?\s*uses:\s*([^@\s'"]+)@([^\s#'"]+)\s*(?:#\s*(.*?))?\s*$/;
  files.forEach(function (f) {
    var lines = fs.readFileSync(path.join(WORKFLOWS_DIR, f), "utf8").split(/\r?\n/);
    lines.forEach(function (line, i) {
      var m = re.exec(line);
      if (!m) return;
      var pathPart = m[1], ref = m[2], comment = (m[3] || "").trim();
      if (pathPart.indexOf("./") === 0 || pathPart.indexOf("docker://") === 0) return;
      var segs = pathPart.split("/");
      if (segs.length < 2) return;
      uses.push({
        ownerRepo: segs[0] + "/" + segs[1], fullPath: pathPart, ref: ref, comment: comment,
        loc: ".github/workflows/" + f + ":" + (i + 1),
      });
    });
  });
  return uses;
}

var _resolveCache = {};
function resolveLatest(ownerRepo) {
  if (_resolveCache[ownerRepo] !== undefined) return _resolveCache[ownerRepo];
  var tag = ghApi("repos/" + ownerRepo + "/releases/latest", ".tag_name");
  if (!tag) {
    // No GitHub Release — pick the highest semver tag (not the newest-created).
    var raw = ghApi("repos/" + ownerRepo + "/tags?per_page=100", ".[].name");
    if (raw) {
      var tags = raw.split("\n").map(function (t) { return t.trim(); })
        .filter(function (t) { return /^v?\d+\.\d+\.\d+$/.test(t); });
      tags.sort(semverCmp);
      tag = tags.length ? tags[tags.length - 1] : null;
    }
  }
  if (!tag) { _resolveCache[ownerRepo] = null; return null; }
  var sha = ghApi("repos/" + ownerRepo + "/commits/" + tag, ".sha");
  var out = sha ? { tag: tag, sha: sha } : null;
  _resolveCache[ownerRepo] = out;
  return out;
}

// ---- gate: actions-currency ---------------------------------------------

function actionsGate() {
  console.log(bold("\n== actions-currency =="));
  var uses = parseWorkflowUses();
  if (uses.length === 0) { console.log(dim("  no workflow `uses:` references found")); return 0; }

  var byAction = {};
  uses.forEach(function (u) { (byAction[u.ownerRepo] = byAction[u.ownerRepo] || []).push(u); });

  if (!ghAvailable()) {
    console.log(red("  ✗ `gh` CLI unavailable — cannot verify action currency (run `gh auth login`)"));
    return 1;
  }

  var stale = [], unresolved = [], ok = 0;
  Object.keys(byAction).sort().forEach(function (ownerRepo) {
    var sites = byAction[ownerRepo];
    var latest = resolveLatest(ownerRepo);
    if (!latest) { unresolved.push({ ownerRepo: ownerRepo, sites: sites }); return; }
    var bad = [];
    sites.forEach(function (s) {
      var reusable = isReusableWorkflow(s.fullPath);
      var isSha = SHA40_RE.test(s.ref);
      if (reusable) {
        // tag-pin REQUIRED; stale only if the tag is behind the latest release.
        if (isSha) bad.push({ site: s, why: "reusable workflow SHA-pinned — must be a semver tag" });
        else if (semverCmp(s.ref, latest.tag) < 0) bad.push({ site: s, why: "tag " + s.ref + " < latest " + latest.tag });
        return;
      }
      if (!isSha) {
        var note = "";
        var pm = refMajor(s.ref), lm = refMajor(latest.tag);
        if (pm !== null && lm !== null && lm > pm) note = "  ⚠ MAJOR " + s.ref + " → " + latest.tag + " — review breaking changes";
        bad.push({ site: s, why: "pinned to " + s.ref + " (not a commit SHA)" + note });
      } else if (s.ref.toLowerCase() !== latest.sha.toLowerCase()) {
        bad.push({ site: s, why: "SHA " + s.ref.slice(0, 12) + "… ≠ latest " + latest.tag });
      } else {
        // Compare the comment's semver against the semver carried in the latest
        // release tag, not the raw tag — some actions tag releases with a prefix
        // (e.g. codeql-action's `codeql-bundle-vX.Y.Z`), so a literal tag compare
        // would flag a correctly-pinned action as stale. Skip when either side
        // has no parseable X.Y.Z.
        var cs = commentSemver(s.comment);
        var lts = commentSemver(latest.tag);
        if (cs && lts && cs !== lts) bad.push({ site: s, why: "comment `" + s.comment + "` ≠ latest " + latest.tag });
      }
    });
    if (bad.length) stale.push({ ownerRepo: ownerRepo, latest: latest, bad: bad });
    else ok += sites.length;
  });

  console.log(dim("  " + Object.keys(byAction).length + " action(s), " + uses.length + " pin site(s); " + ok + " current"));

  if (unresolved.length) {
    console.log(red("\n  ⚠ could not resolve the latest release for:"));
    unresolved.forEach(function (u) {
      console.log("    " + u.ownerRepo + dim("  (" + u.sites.map(function (s) { return s.loc; }).join(", ") + ")"));
    });
  }
  if (stale.length === 0 && unresolved.length === 0) {
    console.log(green("  OK — every action pinned to its latest release"));
    return 0;
  }

  stale.forEach(function (a) {
    console.log(red("\n  ✗ " + a.ownerRepo) + " is stale:");
    a.bad.forEach(function (b) { console.log("      " + dim("· ") + b.why + dim("  (" + b.site.loc + ")")); });
    var paths = {};
    a.bad.forEach(function (b) { (paths[b.site.fullPath] = paths[b.site.fullPath] || []).push(b.site.loc); });
    Object.keys(paths).forEach(function (fp) {
      console.log(yellow("    paste-ready pin:"));
      if (isReusableWorkflow(fp)) {
        console.log("      " + green(fp + "@" + a.latest.tag) + dim("  (reusable workflow — tag pin required, not SHA)"));
      } else {
        console.log("      " + green(fp + "@" + a.latest.sha + " # " + a.latest.tag));
      }
      console.log(dim("    used at:"));
      paths[fp].forEach(function (loc) { console.log(dim("      " + loc)); });
    });
  });
  return 1;
}

// ---- gate: vendor-currency ----------------------------------------------

function vendorGate() {
  console.log(bold("\n== vendor-currency =="));
  var manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
  var bj = manifest.packages && manifest.packages.blamejs;
  if (!bj) { console.log(red("  ✗ no blamejs entry in MANIFEST.json")); return 1; }
  if (!ghAvailable()) {
    console.log(red("  ✗ `gh` CLI unavailable — cannot verify blamejs currency"));
    return 1;
  }
  var vendoredTag = bj.tag || ("v" + bj.version);
  var latestTag = ghApi("repos/blamejs/blamejs/releases/latest", ".tag_name");
  if (!latestTag) { console.log(red("  ✗ could not resolve the latest blamejs release")); return 1; }
  console.log(dim("  blamejs vendored " + vendoredTag + ", latest " + latestTag));
  var cmp = semverCmp(vendoredTag, latestTag);
  if (cmp === 0) { console.log(green("  OK — vendored blamejs is at the latest release")); return 0; }
  if (cmp > 0) {
    console.log(yellow("  ⚠ vendored " + vendoredTag + " is AHEAD of the latest published release " + latestTag + " — not failing"));
    return 0;
  }
  console.log(red("\n  ✗ blamejs is stale: vendored " + vendoredTag + " → latest " + latestTag));
  console.log(yellow("    paste-ready pin:"));
  console.log("      " + green("blamejs/blamejs@" + latestTag) + dim("   (refresh: bash scripts/vendor-update.sh blamejs)"));
  console.log(dim("    pinned at: lib/vendor/MANIFEST.json  (packages.blamejs.tag / .version)"));
  console.log(dim("    note: blamejs.components (noble, peculiar, simplewebauthn, SecLists) refresh transitively with the bump"));
  return 1;
}

// ---- gate: patterns-currency (advisory) ---------------------------------

// blamejs codebase-patterns detectors confirmed not-applicable to HS, or covered
// elsewhere — excluded from the advisory so it stays signal. Reviewed 2026-05-30;
// when blamejs adds a detector that lands here purely as N/A, add it (with reason).
var PATTERNS_NA = {
  "ai-disclosure-on-request-without-requested-gate": "blamejs AI-agent surface; HS has none",
  "archive-gz-without-safedecompress": "HS never decompresses untrusted input",
  "archive-wrap-partial-recipient": "blamejs multi-recipient archive; N/A to HS",
  "backup-adapter-storage-without-posture-check": "blamejs backup-adapter internals; HS backup is its own",
  "primitive-unreachable": "blamejs-internal primitive-wiring test",
  "gitleaks-entropy": "HS covers via its gitleaks-entropy-unallowed detector",
  "slsa-framework-action-not-sha-pinned": "HS covers via this runner's actions-currency gate",
  "numeric-opt-no-bounds-check": "HS covers via its numeric-opt-Infinity detector",
  "from-base64url-untrapped": "HS decodes via Buffer.from(x,'base64'); never blamejs's .fromBase64Url() helper",
  "no-number-money-arithmetic": "HS has no monetary/billing domain",
  "wildcard-suffix-match-without-single-label-check": "wildcard SNI/SAN lives in vendored blamejs; HS delegates CORS origin matching to b.middleware.cors",
  "list-without-pagination": "HS centralizes object-store pagination in the s3-client.js walker; callers delegate via S3Client.list",
  "inline-numeric-bounds-cascade": "blamejs opts-factory primitive shape; HS authors no framework primitives (consumes b.* via the public surface)",
  "inline-require-non-empty-string-validation": "blamejs opts-factory primitive shape; HS authors no framework primitives (consumes b.* via the public surface)",
  "internal-narrative-comment": "blamejs-specific label vocabulary (SUBSTRATE-/MAIL-/Codex P#/blamejs PR #N); HS lib/ comments carry none (0 sites); HS's no-internal-narrative discipline targets Phase/Sweep/Tier/Slice, enforced via the release-notes leak-vocabulary blocklist — a HS gate, if wanted, is a new detector, not this port.",
  "hand-rolled-sql": "blamejs detector for migrating its OWN data layer (clusterStorage/externalDb + the b.sql builder + _blamejs_* framework tables) onto b.sql; HS owns a deliberate standalone SQLite substrate (lib/db.js, its own prepared-statement handle + schema migration) and consumes none of that data layer, so there is no b.sql to migrate onto — HS already uses the portable b.safeSql.quoteIdentifier for identifier-injection safety (lib/db.js).",
};

// Extract the detector class-id set from a codebase-patterns gate file.
function extractDetectorIds(file, regexes) {
  if (!fs.existsSync(file)) return null;
  var src = fs.readFileSync(file, "utf8");
  var set = {};
  regexes.forEach(function (re) {
    re.lastIndex = 0;
    var m;
    while ((m = re.exec(src)) !== null) set[m[1].toLowerCase()] = true;
  });
  return Object.keys(set);
}

// Advisory: surface blamejs codebase-patterns detector classes that HS's own gate
// hasn't adopted (candidate new checks / features). Never fails the cut — adopting
// a check is a judgement call, not a release blocker. blamejs registers detectors
// in a `"class-id": 1,` table; HS registers them via _filterMarkers(..,"id") +
// `// class: id` comments.
function patternsGate() {
  console.log(bold("\n== patterns-currency (advisory) =="));
  var bjIds = extractDetectorIds(BJ_PATTERNS_GATE, [/^\s*"([a-z][a-z0-9-]+)":\s*(?:1|true),?\s*$/gm]);
  var hsIds = extractDetectorIds(HS_PATTERNS_GATE, [
    /_filterMarkers\([^,]+,\s*"([a-zA-Z][a-zA-Z0-9-]+)"/g,
    /\/\/\s*class:\s*([a-zA-Z][a-zA-Z0-9-]+)/g,
    // KNOWN_ANTIPATTERNS registry entries register their class via `id: "..."`.
    /^\s*id:\s*"([a-zA-Z][a-zA-Z0-9-]+)"/gm,
  ]);
  if (!bjIds || !hsIds) {
    console.log(yellow("  ⚠ could not locate a codebase-patterns gate — skipping (blamejs gate moved?)"));
    return 0;
  }
  var hsSet = {};
  hsIds.forEach(function (x) { hsSet[x] = true; });
  var drift = bjIds.filter(function (x) { return !hsSet[x] && !PATTERNS_NA[x]; }).sort();
  var naCount = bjIds.filter(function (x) { return !hsSet[x] && PATTERNS_NA[x]; }).length;
  console.log(dim("  blamejs gate " + bjIds.length + " detectors · HS gate " + hsIds.length + " · " + naCount + " known-N/A excluded"));
  if (drift.length === 0) {
    console.log(green("  OK — HS's gate covers every applicable blamejs detector"));
    return 0;
  }
  console.log(yellow("  ⚠ blamejs has " + drift.length + " detector class(es) not in HS's gate — review for adoption:"));
  drift.forEach(function (d) { console.log("      " + cyan(d)); });
  console.log(dim("  Some may be renames of an existing HS detector. Assess each + port the worthwhile ones"));
  console.log(dim("  into tests/lint/codebase-patterns.test.js (add confirmed-N/A ids to PATTERNS_NA here)."));
  console.log(dim("  ADVISORY — does not block the cut."));
  return 0;
}

// ---- local gate runner --------------------------------------------------

// Run a node script as a gate; print pass/fail, return 0/1.
function nodeGate(label, args) {
  process.stdout.write("  " + label + " … ");
  try {
    cp.execFileSync("node", args, { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] });
    console.log(green("ok"));
    return 0;
  } catch (e) {
    console.log(red("FAIL"));
    var out = ((e.stdout || "") + (e.stderr || "")).toString().trim();
    if (out) console.log(dim(out.split("\n").slice(0, 25).map(function (l) { return "      " + l; }).join("\n")));
    return 1;
  }
}

// ESLint gate — runs the canonical eslint.config.js with --max-warnings=0
// (CI parity: the Docker lint job fails on any warning). Uses the eslint
// already installed under tests/node_modules so no extra install is needed;
// skips with a warning on a fresh clone where tests deps aren't present yet.
function eslintGate() {
  var fsLocal = require("node:fs");
  var eslintBin = path.join(REPO, "tests", "node_modules", "eslint", "bin", "eslint.js");
  process.stdout.write("  eslint … ");
  if (!fsLocal.existsSync(eslintBin)) {
    console.log(yellow("skipped (tests/node_modules eslint not installed)"));
    return 0;
  }
  try {
    cp.execFileSync("node", [eslintBin, "--config", "eslint.config.js", ".", "--max-warnings=0"], {
      cwd: REPO,
      stdio: ["ignore", "pipe", "pipe"],
      env: Object.assign({}, process.env, { NODE_PATH: path.join(REPO, "tests", "node_modules") }),
    });
    console.log(green("ok"));
    return 0;
  } catch (e2) {
    console.log(red("FAIL"));
    var out2 = ((e2.stdout || "") + (e2.stderr || "")).toString().trim();
    if (out2) console.log(dim(out2.split("\n").slice(0, 30).map(function (l) { return "      " + l; }).join("\n")));
    return 1;
  }
}

// ---- stages -------------------------------------------------------------

// Newest Docker-workflow run (any trigger) — used only for informational status.
function dockerRun(jq) {
  var out = capture("gh", ["run", "list", "--repo", PUBLIC_SLUG, "--workflow=Docker", "--limit", "1", "--json", jq]);
  if (!out) return null;
  try { return JSON.parse(out)[0] || null; } catch (_e) { return null; }
}

// The Docker run for a specific tag push (head_branch == the tag name).
function dockerRunForTag(tag, jq) {
  var fields = jq.indexOf("headBranch") === -1 ? jq + ",headBranch" : jq;
  var out = capture("gh", ["run", "list", "--repo", PUBLIC_SLUG, "--workflow=Docker", "--branch", tag, "--limit", "1", "--json", fields]);
  if (out) { try { var first = JSON.parse(out)[0]; if (first) return first; } catch (_e) { /* fall through */ } }
  // Fallback: scan recent runs for one whose head ref is the tag.
  out = capture("gh", ["run", "list", "--repo", PUBLIC_SLUG, "--workflow=Docker", "--limit", "15", "--json", fields]);
  if (out) {
    try {
      var arr = JSON.parse(out) || [];
      for (var i = 0; i < arr.length; i++) { if (arr[i].headBranch === tag) return arr[i]; }
    } catch (_e) { /* none */ }
  }
  return null;
}

function cmdStatus() {
  console.log(bold("\n== status =="));
  console.log(bold("\n  versions"));
  versionConsistency();

  console.log(bold("\n  repos"));
  [["private", REPO], ["public ", PUBLIC_REPO]].forEach(function (r) {
    var name = r[0], dir = r[1];
    if (!fs.existsSync(dir)) { console.log("  " + name + "  " + red("missing (" + dir + ")")); return; }
    var br = gitBranch(dir), clean = gitClean(dir);
    var tag = gitCap(dir, ["describe", "--tags", "--abbrev=0"]) || "—";
    console.log("  " + name + "  branch=" + cyan(br || "?") +
      "  " + (clean ? green("clean") : yellow("dirty")) + "  latest-tag=" + cyan(tag));
  });
  console.log("  sync     " + (fs.existsSync(SYNC_REPO) ? green("present") : red("missing")) + dim("  (" + SYNC_REPO + ")"));

  if (ghAvailable()) {
    console.log(bold("\n  public Docker run (latest)"));
    var r = dockerRun("displayTitle,status,conclusion,url");
    if (r) {
      console.log("  " + cyan(r.displayTitle) + "  " + (r.status === "completed"
        ? (r.conclusion === "success" ? green(r.conclusion) : red(r.conclusion)) : yellow(r.status)));
      console.log(dim("  " + r.url));
    } else { console.log(dim("  (no runs / not authenticated)")); }
  } else {
    console.log(dim("\n  (gh unavailable — skipping Docker run status)"));
  }
  return 0;
}

function cmdBump() {
  console.log(bold("\n== bump =="));
  var cur = pkgVersion();
  if (!SEMVER_RE.test(cur)) {
    console.log(red("  ✗ current version `" + cur + "` is not strict X.Y.Z — refusing to bump (pre-release versions are out of scope)"));
    return 1;
  }
  var nv = bumpVersion(cur, FLAGS.minor);
  console.log("  " + cur + "  →  " + bold(nv) + (FLAGS.minor ? dim("  (minor)") : dim("  (patch)")));

  if (FLAGS.dryRun) { console.log(dim("  --dry-run: not writing files")); }
  else {
    var pkgSrc = fs.readFileSync(PACKAGE_JSON, "utf8");
    fs.writeFileSync(PACKAGE_JSON, pkgSrc.replace(/("version":\s*")[\d.]+(")/, "$1" + nv + "$2"));
    var cSrc = fs.readFileSync(CONSTANTS_JS, "utf8");
    fs.writeFileSync(CONSTANTS_JS, cSrc.replace(/^(\s*version:\s*")[\d.]+(")/m, "$1" + nv + "$2"));
    console.log(green("  bumped package.json + lib/constants.js"));
  }

  var rnPath = releaseNotesPath(nv);
  if (fs.existsSync(rnPath)) { console.log(green("  release-notes/v" + nv + ".json exists")); return 0; }
  if (FLAGS.dryRun) { console.log(yellow("  --dry-run: would scaffold release-notes/v" + nv + ".json")); return 2; }
  var template = {
    version: nv,
    date: new Date().toISOString().slice(0, 10),
    headline: "",
    summary: "",
    sections: [{ heading: "Fixed", items: [{ title: "", body: "" }] }],
  };
  fs.writeFileSync(rnPath, JSON.stringify(template, null, 2) + "\n");
  console.log(yellow("  scaffolded release-notes/v" + nv + ".json — fill headline + sections, then run `changelog` + `preflight`"));
  return 2;
}

function cmdChangelog() {
  console.log(bold("\n== changelog =="));
  if (FLAGS.dryRun) { console.log(dim("  --dry-run: would rebuild CHANGELOG.md from release-notes/")); return 0; }
  try {
    run("node", ["scripts/generate-changelog-entry.js", "--rebuild"], { cwd: REPO });
    console.log(green("  CHANGELOG.md rebuilt — review + include it in the release commit"));
    return 0;
  } catch (_e) {
    console.log(red("  ✗ rebuild failed — a release-notes JSON is likely invalid"));
    return 1;
  }
}

function cmdPreflight() {
  console.log(bold("\n== preflight =="));
  var v = pkgVersion();

  console.log(bold("\n  version agreement"));
  if (!versionConsistency()) {
    console.log(red("\n  ✗ versions disagree — fix the three files (or run `bump`) before cutting"));
    return 3;
  }
  console.log(green("  OK — all three agree on v" + v));

  console.log(bold("\n  local gates"));
  var driftFail = nodeGate("changelog drift", ["scripts/generate-changelog-entry.js", "--check"]);
  var fails = driftFail
    + nodeGate("release-notes rollup", ["scripts/consolidate-release-notes.js", "--check"])
    + nodeGate("changelog extract", ["scripts/check-changelog-extract.js"])
    + nodeGate("codebase patterns", ["tests/lint/codebase-patterns.test.js"])
    + eslintGate();

  var actionsCode = actionsGate();
  var vendorCode = vendorGate();
  patternsGate(); // advisory — surfaces new blamejs codebase-patterns detectors; never blocks

  if (fails || actionsCode || vendorCode) {
    console.log(red("\n  ✗ preflight failed — resolve the above before cutting"));
    if (driftFail) console.log(dim("  changelog drift → run `node scripts/release.js changelog`, then re-stage"));
    return 1;
  }
  console.log(green("\n  preflight OK — ready to cut v" + v));
  return 0;
}

function cmdE2e() {
  console.log(bold("\n== e2e =="));
  if (FLAGS.dryRun) { console.log(dim("  --dry-run: would run node tests/run-all.js in ../hermitstash-sync")); return 0; }
  if (!fs.existsSync(SYNC_REPO)) { console.log(red("  ✗ ../hermitstash-sync not found")); return 1; }
  console.log(dim("  node tests/run-all.js  (cwd ../hermitstash-sync, OPENSSL_CONF cleared)"));
  try {
    // Point the sync runner's server harness at THIS working tree, not its
    // default (../hermitstash, the public mirror = the last synced release).
    // Without this the pre-release E2E silently exercises already-shipped code
    // instead of the changes being cut.
    var e2eEnv = cleanEnv();
    e2eEnv.HERMITSTASH_SERVER_DIR = REPO;
    run("node", ["tests/run-all.js"], { cwd: SYNC_REPO, env: e2eEnv });
    console.log(green("\n  E2E passed"));
    return 0;
  } catch (_e) {
    console.log(red("\n  ✗ E2E failed"));
    return 1;
  }
}

// Commit-message file (multi-line, avoids cross-platform quoting headaches).
function writeCommitMsgFile(subject, body) {
  var f = path.join(os.tmpdir(), "hs-release-msg-" + process.pid + ".txt");
  fs.writeFileSync(f, body ? (subject + "\n\n" + body + "\n") : (subject + "\n"));
  return f;
}

function cmdCommit() {
  console.log(bold("\n== commit (private) =="));
  if (!versionConsistency()) { console.log(red("  ✗ versions disagree — run preflight")); return 3; }
  var v = pkgVersion();
  var rn = releaseNotes(v);
  if (!rn) { console.log(red("  ✗ release-notes/v" + v + ".json missing")); return 2; }
  var subject = commitSubject(v, rn);

  if (gitBranch(REPO) !== "main") { console.log(red("  ✗ private repo not on main")); return 1; }

  var clean = gitClean(REPO);
  if (clean && headIsReleaseCommit(REPO, subject, v)) {
    console.log(dim("  HEAD already carries the v" + v + " release commit — ensuring push"));
  } else if (clean) {
    console.log(yellow("  working tree clean but HEAD is not the v" + v + " release commit"));
    console.log(dim("  (run `bump` + fill release-notes + `changelog`, or check the version bump was committed)"));
    return 1;
  } else {
    var msgFile = writeCommitMsgFile(subject, rn.summary);
    var failed = false;
    try {
      gitAct(REPO, ["add", "-A"]);
      gitAct(REPO, ["commit", "-S", "-F", msgFile]);
      if (willExecute()) {
        if (capture("git", ["-C", REPO, "verify-commit", "HEAD"]) === null) {
          console.log(red("  ✗ commit signature did NOT verify — aborting (check ssh signing key + GH registration)"));
          failed = true;
        } else { console.log(green("  signed commit verified")); }
      }
    } finally { try { fs.unlinkSync(msgFile); } catch (_e) { /* best-effort */ } }
    if (failed) return 1;
  }
  gitAct(REPO, ["push", "origin", "main"]);
  console.log(dim("\n  private CI: https://github.com/" + PRIVATE_SLUG + "/actions"));
  return 0;
}

// sync-to-public.sh wipes the public tree then `git archive | tar -x`. On a
// Dropbox file lock the wipe can fail mid-way; re-running re-attempts it. Only
// retry the known transient lock signature — surface any other failure as-is.
function runSyncScript() {
  for (var attempt = 1; attempt <= 2; attempt++) {
    try {
      cp.execFileSync("bash", ["scripts/sync-to-public.sh"],
        { cwd: REPO, env: cleanEnv(), encoding: "utf8", stdio: ["ignore", "inherit", "pipe"] });
      return true;
    } catch (e) {
      var stderr = ((e && e.stderr) || (e && e.message) || "").toString();
      var transient = /Device or resource busy|cannot remove|Resource temporarily unavailable/i.test(stderr);
      if (attempt === 2 || !transient) {
        if (stderr.trim()) console.log(red("  " + stderr.trim().split("\n").join("\n  ")));
        throw e;
      }
      console.log(yellow("  sync hit a file lock (Dropbox?) — retrying once"));
    }
  }
  return false;
}

function cmdSync() {
  console.log(bold("\n== sync (public) =="));
  if (!fs.existsSync(PUBLIC_REPO)) { console.log(red("  ✗ ../hermitstash not found")); return 1; }
  if (!versionConsistency()) { console.log(red("  ✗ versions disagree — run preflight")); return 3; }
  var v = pkgVersion();
  var rn = releaseNotes(v);
  var subject = commitSubject(v, rn);

  // Refuse BEFORE mutating: the mirror must be built from the release commit,
  // and the public repo must be on main.
  if (!headIsReleaseCommit(REPO, subject, v)) {
    console.log(red("  ✗ private HEAD is not the v" + v + " release commit — run `commit` first"));
    return 1;
  }
  if (gitBranch(PUBLIC_REPO) !== "main") { console.log(red("  ✗ public repo not on main")); return 1; }

  if (!willExecute()) {
    console.log(dim("  would run: bash scripts/sync-to-public.sh"));
    console.log(dim("  would run: git -C <public> add -A && commit -S -F <msg> && push origin main"));
    return 0;
  }
  if (!bashAvailable()) { console.log(red("  ✗ bash not found — install Git Bash / WSL to run sync-to-public.sh")); return 1; }

  runSyncScript();

  if (gitClean(PUBLIC_REPO)) {
    console.log(dim("  public tree already matches private HEAD — nothing to commit"));
  } else {
    var msgFile = writeCommitMsgFile(subject, rn && rn.summary);
    try {
      gitAct(PUBLIC_REPO, ["add", "-A"]);
      gitAct(PUBLIC_REPO, ["commit", "-S", "-F", msgFile]);
    } finally { try { fs.unlinkSync(msgFile); } catch (_e) { /* best-effort */ } }
  }
  gitAct(PUBLIC_REPO, ["push", "origin", "main"]);
  return 0;
}

function tagPointsAtHead(dir, tag) {
  var tagCommit = gitCap(dir, ["rev-list", "-n1", tag]);
  var head = gitCap(dir, ["rev-parse", "HEAD"]);
  return !!tagCommit && tagCommit === head;
}
function remoteHasTag(dir, tag) { return !!gitCap(dir, ["ls-remote", "--tags", "origin", "refs/tags/" + tag]); }

function createSignedTag(name, dir, tag, msg) {
  gitAct(dir, ["tag", "-s", tag, "-m", msg]);
  if (willExecute()) {
    if (capture("git", ["-C", dir, "tag", "-v", tag]) === null) {
      console.log(red("  ✗ " + name + ": tag signature did NOT verify — aborting"));
      return false;
    }
    console.log(green("  " + name + ": signed tag verified"));
  }
  return true;
}

function tagOneRepo(name, dir, tag, msg) {
  if (!fs.existsSync(dir)) { console.log(red("  ✗ " + name + " repo missing")); return 1; }
  var existsLocal = gitCap(dir, ["tag", "-l", tag]);
  if (existsLocal) {
    if (tagPointsAtHead(dir, tag)) {
      console.log(dim("  " + name + ": tag " + tag + " already at HEAD — ensuring push"));
    } else if (remoteHasTag(dir, tag)) {
      console.log(red("  ✗ " + name + ": tag " + tag + " is on the remote but does NOT point at HEAD"));
      console.log(red("     tags are immutable — `bump` a new version rather than moving " + tag));
      return 1;
    } else {
      console.log(yellow("  " + name + ": stale local tag " + tag + " (not at HEAD, not pushed) — recreating at HEAD"));
      gitAct(dir, ["tag", "-d", tag]);
      if (!createSignedTag(name, dir, tag, msg)) return 1;
    }
  } else if (!createSignedTag(name, dir, tag, msg)) {
    return 1;
  }
  try { gitAct(dir, ["push", "origin", tag]); }
  catch (_e) { console.log(red("  ✗ " + name + ": tag push failed")); return 1; }
  if (willExecute() && !remoteHasTag(dir, tag)) {
    console.log(red("  ✗ " + name + ": tag not visible on the remote after push"));
    return 1;
  }
  return 0;
}

function cmdTag() {
  console.log(bold("\n== tag (both repos) =="));
  if (!versionConsistency()) { console.log(red("\n  ✗ versions disagree — run preflight before tagging")); return 3; }
  var v = pkgVersion();
  var tag = "v" + v;
  var rn = releaseNotes(v);
  var msg = tagMessage(v, rn);
  console.log(dim("  tag " + tag + "  message: " + msg));

  var privCode = tagOneRepo("private", REPO, tag, msg);
  var pubCode = tagOneRepo("public ", PUBLIC_REPO, tag, msg);

  if (willExecute() && privCode === 0 && pubCode === 0) {
    console.log(yellow("\n  public tag pushed — Docker build + automatic GitHub Release now in flight"));
    console.log(dim("  watch: node scripts/release.js watch"));
  }
  return (privCode || pubCode) ? 1 : 0;
}

function cmdWatch() {
  console.log(bold("\n== watch =="));
  var v = pkgVersion(), tag = "v" + v;
  if (!ghAvailable()) { console.log(red("  ✗ gh unavailable")); return 1; }

  console.log(bold("\n  CI surfaces"));
  console.log("  private CI    " + dim("https://github.com/" + PRIVATE_SLUG + "/actions"));
  console.log("  public CI     " + dim("https://github.com/" + PUBLIC_SLUG + "/actions"));

  // Poll for the tag-triggered run to register (push propagation lag).
  var r = null;
  for (var i = 0; i < 6; i++) {
    r = dockerRunForTag(tag, "databaseId,url,status,conclusion,displayTitle,headBranch");
    if (r) break;
    console.log(dim("  waiting for the " + tag + " Docker run to register… (" + (i + 1) + "/6)"));
    sleepMs(5000);
  }
  if (!r) {
    console.log(yellow("  no Docker run for " + tag + " yet — re-run `watch` once it registers"));
    return 1;
  }
  console.log("  public Docker " + dim(r.url) + dim("  [" + r.displayTitle + "]"));

  if (r.status !== "completed") {
    console.log(dim("\n  following run " + r.databaseId + " to completion…"));
    try { run("gh", ["run", "watch", String(r.databaseId), "--repo", PUBLIC_SLUG, "--exit-status"]); }
    catch (_e) {
      console.log(red("\n  ✗ Docker run did not succeed — gh run view " + r.databaseId + " --repo " + PUBLIC_SLUG + " --log-failed"));
      return 1;
    }
  } else if (r.conclusion !== "success") {
    console.log(red("  ✗ the " + tag + " Docker run concluded " + r.conclusion));
    return 1;
  }

  var rel = capture("gh", ["release", "view", tag, "--repo", PUBLIC_SLUG, "--json", "name,url"]);
  if (rel) {
    try { console.log(green("\n  GitHub Release created: ") + dim(JSON.parse(rel).url)); }
    catch (_e) { console.log(green("\n  GitHub Release present")); }
  } else {
    console.log(yellow("\n  ⚠ Release " + tag + " not visible yet — the `release` job may still be finishing"));
  }
  return 0;
}

function cmdTrivy() {
  console.log(bold("\n== trivy =="));
  if (!ghAvailable()) { console.log(red("  ✗ gh unavailable")); return 1; }
  var tag = "v" + pkgVersion();
  var r = dockerRunForTag(tag, "databaseId,url,headBranch") || dockerRun("databaseId,url");
  if (!r) { console.log(yellow("  no Docker run found")); return 1; }
  console.log("  Triage the post-release Trivy scan for the next patch:");
  console.log(dim("  run:  " + r.url));
  console.log(dim("  logs: gh run view " + r.databaseId + " --repo " + PUBLIC_SLUG + " --log | grep -iA40 trivy"));
  console.log(dim("  Visibility step (exit 0) lists ALL findings incl. unfixed; the gate step (exit 1) fails only on"));
  console.log(dim("  fixable HIGH/CRITICAL. Note every finding → address what we can next patch."));
  return 0;
}

function cmdAll() {
  console.log(bold("\n=== release: all stages ==="));
  var stages = [
    ["changelog", cmdChangelog],
    ["preflight", cmdPreflight],
    ["e2e", cmdE2e],
    ["commit", cmdCommit],
    ["sync", cmdSync],
    ["tag", cmdTag],
  ];
  for (var i = 0; i < stages.length; i++) {
    var code = stages[i][1]();
    if (code !== 0) {
      console.log(red("\n✗ stopped at `" + stages[i][0] + "` (exit " + code + ")"));
      return code;
    }
  }
  if (!willExecute()) {
    console.log(yellow("\n  preview complete — nothing was pushed. Re-run with --yes to cut, then `watch`."));
    return 0;
  }
  var w = cmdWatch();
  if (w !== 0) return w;
  return cmdTrivy();
}

function cmdHelp() {
  console.log([
    bold("release.js — staged release runner"),
    "",
    "  node scripts/release.js <stage> [--minor] [--yes] [--dry-run]",
    "",
    "  " + bold("read-only / gates"),
    "    status     versions, repo state, latest tags, in-flight Docker run",
    "    preflight  version agreement + changelog/rollup/extract/pattern gates + currency gates",
    "    actions    actions-currency gate only (paste-ready owner/repo@<sha> # vX.Y.Z)",
    "    vendor     vendor-currency gate only (blamejs)",
    "    patterns   patterns-currency advisory — new blamejs codebase-patterns detectors to adopt",
    "    e2e        full suite from ../hermitstash-sync",
    "    watch      follow the tag's public Docker run + confirm the GitHub Release",
    "    trivy      point at the tag's post-release Trivy scan",
    "",
    "  " + bold("prep (local edits)"),
    "    bump       bump patch (or --minor) in constants.js + package.json; scaffold release-notes",
    "    changelog  rebuild CHANGELOG.md from release-notes/",
    "",
    "  " + bold("mutating (need --yes; otherwise preview)"),
    "    commit     signed commit + push on private main",
    "    sync       mirror to ../hermitstash + signed commit + push on public main",
    "    tag        signed vX.Y.Z on BOTH repos + push (public push triggers Docker + Release)",
    "    all        changelog → preflight → e2e → commit → sync → tag → watch → trivy",
    "",
    "  typical cut:  bump → (edit release-notes) → changelog → preflight → e2e → all --yes",
    "",
  ].join("\n"));
  return 0;
}

// ---- dispatch -----------------------------------------------------------

function main() {
  var argv = process.argv.slice(2);
  FLAGS.minor = argv.indexOf("--minor") !== -1;
  FLAGS.yes = argv.indexOf("--yes") !== -1;
  FLAGS.dryRun = argv.indexOf("--dry-run") !== -1;
  var sub = argv.filter(function (a) { return a.charAt(0) !== "-"; })[0] || "help";

  var stages = {
    status: cmdStatus, bump: cmdBump, changelog: cmdChangelog, preflight: cmdPreflight, e2e: cmdE2e,
    actions: actionsGate, vendor: vendorGate, patterns: patternsGate, commit: cmdCommit, sync: cmdSync,
    tag: cmdTag, watch: cmdWatch, trivy: cmdTrivy, all: cmdAll, help: cmdHelp,
  };
  var fn = stages[sub];
  if (!fn) { console.error(red("release: unknown stage `" + sub + "`")); cmdHelp(); process.exit(1); }

  var code;
  try { code = fn(); }
  catch (e) { console.error(red("\nrelease: " + (e && e.message ? e.message : e))); process.exit(1); }
  process.exit(code || 0);
}

main();
