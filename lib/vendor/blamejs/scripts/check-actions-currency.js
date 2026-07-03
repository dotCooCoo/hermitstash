// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * GitHub-Actions-currency gate — the sibling of
 * `scripts/check-vendor-currency.js` for the CI/CD supply chain.
 *
 * Walks every `.github/workflows/*.yml`, reads each SHA-pinned
 * `uses: owner/repo[/subpath]@<sha>  # vX.Y.Z` reference, and asserts
 * the pinned version (from the trailing comment the pinact discipline
 * requires) matches the latest upstream release. A stale action
 * becomes a release blocker HERE — caught in the pre-merge gate suite
 * — instead of being surfaced after-the-fact by a Dependabot PR.
 *
 * Run locally:
 *   node scripts/check-actions-currency.js
 *   node scripts/check-actions-currency.js --json     // structured output
 *   node scripts/check-actions-currency.js --warn     // exit 0, print only
 *   node scripts/check-actions-currency.js --fix       // rewrite stale pins
 *                                                       // to the latest SHA +
 *                                                       // version comment,
 *                                                       // then exit 0
 *
 * `--fix` applies the same latest-release SHA the gate already resolves —
 * every `owner/repo[/subpath]@<sha>  # vX.Y.Z` reference to a stale action
 * is rewritten in place. Re-run without `--fix` (or let CI) to verify.
 *
 * Run in CI: the workflow passes GITHUB_TOKEN in the environment so the
 * GitHub API gives the authenticated 5000/hour budget instead of the
 * 60/hour unauthenticated per-IP limit. `stale` fails the gate;
 * transient `api-error` results are advisory unless
 * BLAMEJS_ACTIONS_CURRENCY_STRICT=1 converts them into hard fails too.
 *
 * Actions deliberately pinned to an older major (a new major the repo
 * has not adopted) carry a SPECIAL_MAP entry pinning the expected
 * major so the gate doesn't fight an intentional hold.
 */

var fs    = require("fs");
var path  = require("path");
var https = require("https");

var WORKFLOWS_DIR = path.join(__dirname, "..", ".github", "workflows");

var WARN_ONLY  = process.argv.indexOf("--warn") !== -1;
var JSON_OUT   = process.argv.indexOf("--json") !== -1;
var DO_FIX     = process.argv.indexOf("--fix") !== -1;
var TIMEOUT_MS = 10000;

// Per-action overrides. Keyed by "owner/repo".
//   { type: "hold-major", major: N, reason: "..." } — only flag stale
//        WITHIN the pinned major; a newer major is an intentional hold.
//   { type: "skip", reason: "..." }                 — never flag.
var SPECIAL_MAP = {
  // (none — every pinned action tracks upstream latest)
};

function _githubGet(apiPath) {
  return new Promise(function (resolve, reject) {
    var headers = {
      "User-Agent": "blamejs-actions-currency/1",
      "Accept":     "application/vnd.github+json",
    };
    // Authenticated requests get the 5000/hour budget. Both env names
    // are accepted (GITHUB_TOKEN in Actions, GH_TOKEN for local gh).
    var token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
    if (token) headers.Authorization = "Bearer " + token;
    var req = https.get("https://api.github.com" + apiPath, { timeout: TIMEOUT_MS, headers: headers }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        if (res.statusCode !== 200) {
          return reject(new Error("github " + apiPath + " status " + res.statusCode));
        }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch (e) { reject(e); }
      });
    });
    req.on("timeout", function () { req.destroy(new Error("github " + apiPath + " timed out after " + TIMEOUT_MS + "ms")); });
    req.on("error", reject);
  });
}

async function _resolveSha(ownerRepo, ref) {
  // Resolve a tag to the COMMIT sha it points at — exactly what the
  // pinact discipline pins (`owner/repo@<commit-sha>  # tag`). The
  // commits endpoint dereferences annotated tags to their commit.
  var c = await _githubGet("/repos/" + ownerRepo + "/commits/" + encodeURIComponent(ref));
  if (!c || typeof c.sha !== "string") throw new Error("could not resolve sha for " + ownerRepo + "@" + ref);
  return c.sha;
}

// Fetch the supply-chain review material for a bump: the commit range
// between the pinned SHA and the new SHA (what actually changed), plus the
// release notes for the new tag. A human reviews this before trusting the
// pin — a compromised release surfaces here as an unexpected commit or an
// author/change that doesn't match the version bump.
async function _releaseChangelog(ownerRepo, oldSha, newTag, newSha) {
  var out = {
    compareUrl: "https://github.com/" + ownerRepo + "/compare/" + oldSha + "..." + newSha,
    commits: [], files: [], body: "", compareError: null,
  };
  try {
    var cmp = await _githubGet("/repos/" + ownerRepo + "/compare/" + oldSha + "..." + newSha);
    if (cmp && cmp.html_url) out.compareUrl = cmp.html_url;
    if (cmp && Array.isArray(cmp.commits)) {
      out.commits = cmp.commits.map(function (c) {
        var msg = ((c.commit && c.commit.message) || "").split("\n")[0];
        var who = (c.author && c.author.login) || (c.commit && c.commit.author && c.commit.author.name) || "?";
        return (c.sha || "").slice(0, 10) + "  " + who + "  " + msg;
      });
    }
    if (cmp && Array.isArray(cmp.files)) {
      // The actual code change per file. GitHub omits `.patch` for files
      // above its diff-size limit (large minified dist bundles) — those are
      // flagged so a reviewer knows to inspect them via the compare URL.
      out.files = cmp.files.map(function (f) {
        return {
          name: f.filename, status: f.status,
          add: f.additions, del: f.deletions,
          patch: typeof f.patch === "string" ? f.patch : null,
        };
      });
    }
  } catch (e) { out.compareError = (e && e.message) || String(e); }
  try {
    var rel = await _githubGet("/repos/" + ownerRepo + "/releases/tags/" + encodeURIComponent(newTag));
    if (rel && typeof rel.body === "string") out.body = rel.body;
  } catch (_e) { /* action ships tags without a GitHub Release body */ }
  return out;
}

async function _latestVersion(ownerRepo) {
  // Prefer the published "latest" release tag; fall back to the
  // highest semver tag for actions that ship tags without GitHub
  // Releases (e.g. ludeeus/action-shellcheck). Returns { tag, sha }
  // so the report can hand back a ready-to-paste pin line.
  var tag = null;
  try {
    var rel = await _githubGet("/repos/" + ownerRepo + "/releases/latest");
    // Only trust the release tag when it is semver-shaped. Some repos
    // (github/codeql-action) publish a non-semver bundle tag as their
    // "latest release" (codeql-bundle-vX.Y.Z) while the ACTION is
    // versioned on separate vN.N.N tags — fall through to tags then.
    if (rel && typeof rel.tag_name === "string" && _semverParse(rel.tag_name)) tag = rel.tag_name;
  } catch (_e) { /* fall through to tags */ }
  if (!tag) {
    var tags = await _githubGet("/repos/" + ownerRepo + "/tags?per_page=100");
    if (!Array.isArray(tags) || tags.length === 0) {
      throw new Error("no releases or tags for " + ownerRepo);
    }
    var best = null;
    for (var i = 0; i < tags.length; i++) {
      var p = _semverParse(tags[i].name);
      if (p && (!best || _semverCompare(p, best.parsed) > 0)) {
        best = { name: tags[i].name, parsed: p };
      }
    }
    if (!best) throw new Error("no semver-shaped tag for " + ownerRepo);
    tag = best.name;
  }
  return { tag: tag, sha: await _resolveSha(ownerRepo, tag) };
}

function _semverParse(v) {
  // Accept partial tags (v4 / v4.1) by treating missing segments as 0.
  var m = String(v).match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2] || "0", 10), parseInt(m[3] || "0", 10)];
}

function _semverCompare(a, b) {
  if (!a || !b) return 0;
  for (var i = 0; i < 3; i++) {
    if (a[i] > b[i]) return  1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

// Collect distinct SHA-pinned actions across every workflow file.
// Returns { "owner/repo": { version, refs: [{ file, line, subpath }] } }.
function _collectPinnedActions() {
  var out = {};
  var files = fs.readdirSync(WORKFLOWS_DIR).filter(function (f) {
    return f.endsWith(".yml") || f.endsWith(".yaml");
  });
  // `uses: owner/repo[/subpath]@<40-hex-sha>  # vX.Y[.Z]`
  var re = /uses:\s*([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)(\/[^@\s]+)?@([0-9a-f]{40})\s*#\s*v?(\d+(?:\.\d+){0,2})/;
  for (var f = 0; f < files.length; f++) {
    var rel = ".github/workflows/" + files[f];
    var lines = fs.readFileSync(path.join(WORKFLOWS_DIR, files[f]), "utf8").split("\n");
    for (var L = 0; L < lines.length; L++) {
      var m = lines[L].match(re);
      if (!m) continue;
      var ownerRepo = m[1];
      var subpath   = m[2] || "";
      var sha       = m[3];
      var version   = m[4];
      if (!out[ownerRepo]) out[ownerRepo] = { version: version, sha: sha, refs: [] };
      out[ownerRepo].refs.push({ file: rel, line: L + 1, subpath: subpath });
      // If the same repo is pinned at two different versions across
      // files, record the lowest so a partial bump still flags.
      if (_semverCompare(_semverParse(version), _semverParse(out[ownerRepo].version)) < 0) {
        out[ownerRepo].version = version;
      }
    }
  }
  return out;
}

async function _checkOne(ownerRepo, entry) {
  var special = SPECIAL_MAP[ownerRepo];
  if (special && special.type === "skip") {
    return { action: ownerRepo, status: "skipped", reason: special.reason, pinned: entry.version };
  }
  var pinned = _semverParse(entry.version);
  try {
    var info = await _latestVersion(ownerRepo);
    var latest = _semverParse(info.tag);
    var cmp = _semverCompare(pinned, latest);
    var status = cmp >= 0 ? "current" : "stale";
    if (special && special.type === "hold-major" && latest && latest[0] > special.major) {
      // A newer major exists but the repo intentionally holds an
      // older major — only flag stale WITHIN the held major.
      status = "current";
    }
    return {
      action:    ownerRepo,
      pinned:    entry.version,
      oldSha:    entry.sha,
      latest:    info.tag,
      latestSha: info.sha,
      status:    status,
      refs:      entry.refs,
    };
  } catch (e) {
    return {
      action: ownerRepo,
      pinned: entry.version,
      status: "api-error",
      error:  (e && e.message) || String(e),
      refs:   entry.refs,
    };
  }
}

async function main() {
  var pinned = _collectPinnedActions();
  var actions = Object.keys(pinned).sort();
  var results = [];
  // Sequential + polite — the action count is small and serial GETs
  // keep us well inside the API budget on shared CI IPs.
  for (var i = 0; i < actions.length; i++) {
    results.push(await _checkOne(actions[i], pinned[actions[i]]));
  }

  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({ results: results }, null, 2) + "\n");
  } else {
    process.stdout.write("[actions-currency] " + actions.length + " SHA-pinned action(s) inspected:\n");
    for (var j = 0; j < results.length; j++) {
      var r = results[j];
      var label = r.status === "current"   ? "OK"
                : r.status === "stale"     ? "STALE"
                : r.status === "api-error" ? "ERR"
                : r.status === "skipped"   ? "skip"
                :                            r.status;
      var line = "  [" + label + "] " + r.action + "  " + r.pinned;
      if (r.latest) line += " -> " + r.latest;
      if (r.reason) line += "  (" + r.reason + ")";
      if (r.error)  line += "  (api: " + r.error + ")";
      process.stdout.write(line + "\n");
      // For stale entries, print a ready-to-paste pin line + every
      // file:line that needs the bump, so updating is copy-paste.
      if (r.status === "stale" && r.latestSha) {
        process.stdout.write("        pin:  " + r.action + "@" + r.latestSha + "  # " + r.latest + "\n");
        for (var rf = 0; rf < (r.refs || []).length; rf++) {
          process.stdout.write("        used: " + r.refs[rf].file + ":" + r.refs[rf].line + "\n");
        }
      }
    }
  }

  var stale   = results.filter(function (r) { return r.status === "stale"; });
  var errored = results.filter(function (r) { return r.status === "api-error"; });

  if (DO_FIX) {
    var byFile = {};
    var fixable = stale.filter(function (r) { return r.latestSha && r.latest; });
    for (var fx = 0; fx < fixable.length; fx++) {
      var fr = fixable[fx];
      var tag = /^v/.test(fr.latest) ? fr.latest : "v" + fr.latest;
      // Supply-chain review material — printed BEFORE applying so the change
      // between the pinned SHA and the new SHA (the actual commits + authors)
      // and the release notes can be validated. A compromised release shows
      // up here as an unexpected commit / author / change.
      var cl = await _releaseChangelog(fr.action, fr.oldSha, tag, fr.latestSha);
      process.stdout.write("\n=== " + fr.action + "  " + fr.pinned + " -> " + fr.latest + " ===\n");
      process.stdout.write("  old sha: " + fr.oldSha + "\n  new sha: " + fr.latestSha + "\n");
      process.stdout.write("  compare: " + cl.compareUrl + "\n");
      if (cl.commits.length) {
        process.stdout.write("  commits between the two SHAs (" + cl.commits.length + ") [sha  author  subject]:\n");
        for (var ci = 0; ci < cl.commits.length; ci++) process.stdout.write("    " + cl.commits[ci] + "\n");
      } else if (cl.compareError) {
        process.stdout.write("  commits: (compare unavailable: " + cl.compareError + ")\n");
      }
      if (cl.files.length) {
        process.stdout.write("  changed files (" + cl.files.length + "):\n");
        for (var sfi = 0; sfi < cl.files.length; sfi++) {
          var sf = cl.files[sfi];
          process.stdout.write("    [" + sf.status + " +" + sf.add + "/-" + sf.del + "] " + sf.name + "\n");
        }
        process.stdout.write("  code diff (per file, capped at 200 lines):\n");
        for (var dfi = 0; dfi < cl.files.length; dfi++) {
          var df = cl.files[dfi];
          process.stdout.write("    ----- " + df.name + " -----\n");
          if (df.patch === null) {
            process.stdout.write("      (patch omitted by GitHub — file too large / binary; inspect via the compare URL above)\n");
          } else {
            var dl = df.patch.split("\n");
            for (var dk = 0; dk < Math.min(dl.length, 200); dk++) process.stdout.write("      " + dl[dk] + "\n");
            if (dl.length > 200) process.stdout.write("      ... (" + (dl.length - 200) + " more diff line(s) — see compare URL)\n");
          }
        }
      }
      if (cl.body) {
        process.stdout.write("  release notes for " + tag + ":\n");
        var bl = cl.body.split("\n");
        for (var bi = 0; bi < Math.min(bl.length, 40); bi++) process.stdout.write("    " + bl[bi] + "\n");
        if (bl.length > 40) process.stdout.write("    ... (" + (bl.length - 40) + " more line(s))\n");
      }
      var esc = fr.action.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      var re2 = new RegExp("(" + esc + "(?:/[^@\\s]+)?@)[0-9a-f]{40}(\\s*#\\s*)v?\\d+(?:\\.\\d+){0,2}", "g");
      for (var rj = 0; rj < (fr.refs || []).length; rj++) {
        var abs = path.join(__dirname, "..", fr.refs[rj].file);
        if (!(abs in byFile)) byFile[abs] = fs.readFileSync(abs, "utf8");
        byFile[abs] = byFile[abs].replace(re2, "$1" + fr.latestSha + "$2" + tag);
      }
    }
    Object.keys(byFile).forEach(function (abs) { fs.writeFileSync(abs, byFile[abs]); });
    process.stdout.write("\n[actions-currency] --fix: rewrote " + fixable.length + " stale action(s) across " +
      Object.keys(byFile).length + " workflow file(s). REVIEW the changelogs above for supply-chain integrity before committing; re-run without --fix to verify.\n");
    process.exit(0);
  }

  if (WARN_ONLY) {
    if (stale.length || errored.length) {
      process.stdout.write("[actions-currency] --warn: " + stale.length + " stale, " +
        errored.length + " errored — exit 0 anyway\n");
    }
    process.exit(0);
  }

  var strictErrors = process.env.BLAMEJS_ACTIONS_CURRENCY_STRICT === "1";
  if (stale.length > 0 || (strictErrors && errored.length > 0)) {
    process.stdout.write("[actions-currency] FAIL — " + stale.length + " stale, " +
      errored.length + " api-error(s). Bump the pinned SHA + version comment to the latest release.\n");
    process.exit(1);
  }
  process.stdout.write("[actions-currency] OK — every pinned action matches the latest upstream release\n");
  process.exit(0);
}

main().catch(function (e) {
  process.stderr.write("[actions-currency] script crashed: " + (e && e.stack || e) + "\n");
  process.exit(2);
});
