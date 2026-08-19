#!/usr/bin/env node
"use strict";
/**
 * Report blamejs releases published since the one vendored here, filtered by
 * whether they are worth acting on.
 *
 * There are two kinds of "worth acting on", and a naive filter misses the
 * second: a release that CHANGES something these repos already call, and a
 * release that ADDS something they could start calling. Filtering on the
 * primitives currently consumed would have stayed silent on the linear-time
 * regex compiler and on the browser crypto builds — both of which were worth
 * adopting precisely because nothing here used them yet.
 *
 * So any release introducing capability is surfaced with its Added titles, and
 * the judgement about whether to adopt is left to a reader. Only releases that
 * are entirely framework-internal — no additions, nothing touching a consumed
 * primitive, no security wording — are passed over, and those are written to
 * stderr so a skip is auditable rather than invisible.
 *
 * The baseline is the vendored version in lib/vendor/MANIFEST.json, not a
 * saved cursor. Nothing to keep in sync, nothing to go stale, and re-vendoring
 * silences the report for exactly the releases it pulled in.
 *
 *   node scripts/blamejs-watch.js                 # releases since the vendored one
 *   node scripts/blamejs-watch.js --assess 0.18.27 [...]   # classify named releases
 *
 * Exit status: 0 whether or not anything is reported — this is a digest, not a
 * gate. `release.js preflight` owns refusing a cut on a stale vendored tree.
 * A registry or API failure exits non-zero, because silence from a broken
 * fetch is indistinguishable from silence meaning "nothing new".
 */
var cp = require("node:child_process");
var fs = require("node:fs");
var path = require("node:path");

var REPO = path.resolve(__dirname, "..");
var SIBLING_SYNC = path.resolve(REPO, "..", "hermitstash-sync");

var SECURITY = /\bsecurity fix\b|\bvulnerab|\bCVE-|\bexploit|\bdenial of service\b|\bauth(?:entication|orization) bypass\b|\bspoof|\bforge|\bleak(?:s|ed|ing)?\b/i;

// No shell. A `--jq` expression contains spaces and quotes, and with a shell
// those are concatenated rather than escaped — gh receives the fragments as
// separate arguments and refuses them. Node warns about the same construct
// (DEP0190) for the injection risk it carries.
function run(cmd, args) {
  return cp.execFileSync(cmd, args, { encoding: "utf8", maxBuffer: 1 << 26 }).trim();
}

function vendoredVersion() {
  var manifest = JSON.parse(fs.readFileSync(path.join(REPO, "lib", "vendor", "MANIFEST.json"), "utf8"));
  return manifest.packages.blamejs.version;
}

// The primitives these repos actually call.
//
// A grep for `b.<name>` is not enough on its own. `b` is what a minifier names
// its second local, so a vendored browser bundle reports `b.render`, `b.set`
// and a dozen others that have nothing to do with the framework — and
// intersecting with the real export surface does not remove them, because a
// minifier and a framework both like short English words. The narrower test is
// the file's own import: code that never requires blamejs cannot be calling it,
// whatever it names its locals.
// Comments are stripped first, because prose about a primitive is not a call to
// it. This file is the proof: its own header quotes `b.render.stream` out of a
// release note, and scanning itself reported the framework's renderer as
// something these repos depend on. Block comments and whole-line `//` comments
// only — a trailing comment is left alone so a `https://` in one cannot eat the
// code preceding it.
var REQUIRES_BLAMEJS = /require\([^)]*blamejs[^)]*\)/;

function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter(function (line) { return !/^\s*(\/\/|\*)/.test(line); })
    .join("\n");
}

function consumedPrimitives() {
  var surface;
  try {
    surface = new Set(Object.keys(require(path.join(REPO, "lib", "vendor", "blamejs"))));
  } catch (_e) {
    return new Set(); // no vendored tree to read — report everything rather than nothing
  }
  var found = new Set();
  // Three ways a primitive gets reached, because missing one silently drops a
  // release from the digest. `b.foo` is the house style; `require(…).foo` is how
  // lib/scheduler.js takes a single primitive without binding the namespace; and
  // a destructure names them with no `b` in sight.
  var PATTERNS = [
    /\bb\.([a-zA-Z][a-zA-Z0-9]*)/g,
    /require\([^)]*blamejs[^)]*\)\s*\.\s*([a-zA-Z][a-zA-Z0-9]*)/g,
  ];
  var DESTRUCTURE = /\{([^}]*)\}\s*=\s*require\([^)]*blamejs[^)]*\)/g;

  function walk(dir) {
    var entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_e) { return; }
    entries.forEach(function (e) {
      var full = path.join(dir, e.name);
      if (e.isDirectory()) {
        // .scratch holds working notes, not shipped code — a primitive named
        // only in a note is a thing someone considered, not a thing we call.
        if (e.name === "node_modules" || e.name === "vendor" || e.name === ".git"
          || e.name === ".scratch") return;
        walk(full);
        return;
      }
      if (!/\.(js|mjs|cjs)$/.test(e.name)) return;
      // This one file is upstream's own source mirrored into the repo — the same
      // category as lib/vendor, which the directory skip above already covers.
      // Its text names 74 primitives, `b.ai` and `b.calendar` among them, and
      // neither repo calls any of those; it quotes the framework's lint rules
      // rather than using them. Counted as consumption they sit silent until a
      // release happens to touch one, and then the digest reports a primitive in
      // use and asks for a decision that isn't there.
      //
      // Matched by full path, not by the `.snapshot.js` suffix: the suffix is a
      // naming convention anyone may reuse, and a future snapshot that really
      // does call blamejs would be dropped from the digest without a trace —
      // failing silent, in the direction of missing a release we should act on.
      if (/[\\/]tests[\\/]lint[\\/]blamejs-codebase-patterns\.snapshot\.js$/.test(full)) return;
      var src;
      try { src = fs.readFileSync(full, "utf8"); } catch (_e2) { return; }
      if (!REQUIRES_BLAMEJS.test(src)) return;
      var code = stripComments(src);
      var m;
      PATTERNS.forEach(function (re) {
        re.lastIndex = 0;
        while ((m = re.exec(code)) !== null) if (surface.has(m[1])) found.add(m[1]);
      });
      DESTRUCTURE.lastIndex = 0;
      while ((m = DESTRUCTURE.exec(code)) !== null) {
        m[1].split(",").forEach(function (part) {
          // `{ a, b: renamed }` — the exported name is what precedes the colon.
          var name = part.split(":")[0].trim();
          if (surface.has(name)) found.add(name);
        });
      }
    });
  }

  [REPO, SIBLING_SYNC].forEach(function (root) {
    if (fs.existsSync(root)) walk(root);
  });
  return found;
}

function releasesSince(version) {
  var raw = run("gh", ["api", "repos/blamejs/blamejs/releases", "--paginate",
    "--jq", ".[].tag_name"]);
  var tags = raw.split("\n").map(function (t) { return t.trim().replace(/^v/, ""); }).filter(Boolean);
  var out = [];
  for (var i = 0; i < tags.length; i++) {
    if (cmp(tags[i], version) <= 0) break; // releases come newest-first
    out.push(tags[i]);
  }
  return out.reverse(); // oldest-first reads like a changelog
}

function cmp(a, b) {
  var pa = String(a).split(".").map(Number);
  var pb = String(b).split(".").map(Number);
  for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
    var d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

// A failure here is recorded rather than swallowed. Rate limiting, an expired
// token and a transient API error all look identical to "this release has no
// notes", and the difference decides whether the digest is complete — so the
// release is still surfaced (better a bare line than a silent omission) and the
// run exits non-zero so nothing downstream reads the result as a clean sweep.
var fetchFailures = 0;

function notesFor(tag) {
  try {
    return run("gh", ["api", "repos/blamejs/blamejs/releases/tags/v" + tag,
      "--jq", ".name + \"\\n\" + .body"]);
  } catch (e) {
    fetchFailures++;
    process.stderr.write("could not fetch notes for " + tag + ": "
      + String(e && e.message).split("\n")[0] + "\n");
    return null;
  }
}

// Item titles look like:  - **Title of the thing** — prose
function itemTitles(section) {
  var out = [];
  var re = /^-\s+\*\*(.+?)\*\*/gm;
  var m;
  while ((m = re.exec(section)) !== null) out.push(m[1].trim());
  return out;
}

function sectionBody(body, heading) {
  var re = new RegExp("^## " + heading + "\\s*$([\\s\\S]*?)(?=^## |$(?![\\s\\S]))", "m");
  var m = body.match(re);
  return m ? m[1] : "";
}

function assess(tag, consumed) {
  var raw = notesFor(tag);
  if (!raw) {
    return {
      tag: tag, notable: true, headline: "",
      why: ["release notes unavailable — surfacing rather than guessing"],
      added: [], securityTitles: [], hits: [], misses: [],
    };
  }

  var nl = raw.indexOf("\n");
  var headline = (nl === -1 ? raw : raw.slice(0, nl)).replace(/^v[\d.]+\s*—\s*/, "").trim();
  var body = nl === -1 ? "" : raw.slice(nl + 1);

  var added = itemTitles(sectionBody(body, "Added"));
  var securitySection = sectionBody(body, "Security");
  var why = [];

  if (added.length) why.push(added.length + " new " + (added.length === 1 ? "capability" : "capabilities"));
  // A "## Security" heading is the reliable signal; the prose test is a
  // fallback for a security fix filed under Fixed. Matching prose alone missed
  // an entire Security section once, which is the failure mode that matters —
  // a skipped security release looks exactly like no release at all.
  if (securitySection.trim()) why.push("SECURITY section");
  else if (SECURITY.test(body)) why.push("security wording");

  // Every primitive the notes name, split by whether these repos call it. The
  // split is the point of the digest: a security release in a primitive nothing
  // here uses still deserves to be seen, but should be dismissable in one read
  // rather than requiring the notes to be opened.
  var named = {};
  var pre = /\bb\.([a-zA-Z][a-zA-Z0-9]*)/g;
  var pm;
  while ((pm = pre.exec(body)) !== null) named[pm[1]] = true;
  var all = Object.keys(named);
  var hits = all.filter(function (p) { return consumed.has(p); });
  var misses = all.filter(function (p) { return !consumed.has(p); });
  if (hits.length) why.push(hits.length + " consumed primitive" + (hits.length === 1 ? "" : "s"));

  return {
    tag: tag, notable: why.length > 0, why: why, added: added,
    securityTitles: itemTitles(securitySection), hits: hits, misses: misses, headline: headline,
  };
}

function render(a, vendored) {
  var lines = [];
  lines.push("blamejs " + a.tag + " — " + a.headline.slice(0, 200));
  lines.push("  surfaced because: " + a.why.join("; "));
  if (a.securityTitles.length) {
    lines.push("  SECURITY:");
    a.securityTitles.forEach(function (t) { lines.push("    ! " + t); });
  }
  if (a.added.length) {
    lines.push("  new — consider adopting:");
    a.added.forEach(function (t) { lines.push("    + " + t); });
  }
  if (a.hits.length) lines.push("  primitives WE USE: " + a.hits.join(", "));
  if (a.misses.length) {
    lines.push("  primitives we don't: " + a.misses.slice(0, 10).join(", ")
      + (a.misses.length > 10 ? " +" + (a.misses.length - 10) + " more" : ""));
  }
  lines.push("  vendored here: " + vendored + " — assess, then re-vendor BOTH repos if adopting.");
  return lines.join("\n");
}

// ---- upstream issues we filed -------------------------------------------
//
// Filing a defect upstream is half of it: the other half is noticing when the
// fix ships, because that is when it can be adopted. The set is read from
// GitHub rather than kept in a list here, so it cannot fall out of date and it
// picks up everything ever filed from this account.
//
// A closed issue is the actionable one — its fix is in some release, so the
// next vendor bump is worth making deliberately rather than whenever the
// currency gate forces it.
var ISSUE_LIMIT = 500;
function upstreamIssues() {
  var raw;
  try {
    raw = run("gh", ["issue", "list", "--repo", "blamejs/blamejs",
      "--author", "@me", "--state", "all", "--limit", String(ISSUE_LIMIT),
      // stateReason separates a closure that shipped a fix (COMPLETED) from one
      // that did not (NOT_PLANNED, DUPLICATE). Without it, an issue declined
      // upstream would be reported as a fix waiting to be adopted.
      "--json", "number,state,title,closedAt,stateReason"]);
  } catch (_e) {
    return null;   // gh missing or unauthenticated — reported, never treated as "none"
  }
  var parsed;
  try { parsed = JSON.parse(raw); } catch (_e) { return null; }
  // A count equal to the cap means the list was cut off and every total below
  // it would understate. Say so rather than print a confident wrong number —
  // the first version of this asked for 60 and reported 60 filed against 103.
  if (parsed.length >= ISSUE_LIMIT) parsed.truncated = true;
  return parsed;
}

function renderIssues(issues, vendoredAt) {
  if (issues === null) {
    process.stdout.write("filed upstream: could not read the issue list "
      + "(gh unavailable or unauthenticated) — state unknown, not none\n\n");
    return;
  }
  if (!issues.length) return;

  var open = issues.filter(function (i) { return i.state === "OPEN"; });
  var closed = issues.filter(function (i) { return i.state === "CLOSED"; });
  // Only a COMPLETED closure shipped something. Declined and duplicate ones are
  // closed too, and reporting those as fixes would send someone after an
  // upgrade that contains nothing.
  var fixed = closed.filter(function (i) { return i.stateReason === "COMPLETED"; });
  var declined = closed.length - fixed.length;
  // Candidates: fixed after the vendored release was cut, so their fix is in
  // something newer than what is on disk.
  //
  // This is a CANDIDATE set and is deliberately not split into shipped and
  // unshipped. A closure timestamp does not establish which release carries the
  // commit — a fix merged after a tag is cut lands in the next release, a draft
  // can sit for any length of time, and the closure may precede or follow the
  // merge. Sorting on dates would put a confident label on a guess, so the set
  // is reported whole and the release notes settle it. Being told to check three
  // entries costs a minute; being told the wrong one shipped costs a release.
  var candidates = fixed.filter(function (i) {
    return i.closedAt && vendoredAt && i.closedAt > vendoredAt;
  });

  process.stdout.write("upstream issues filed: " + issues.length
    + " · fixed: " + fixed.length
    + (declined ? " · closed without a fix: " + declined : "")
    + " · open: " + open.length
    + (issues.truncated ? "   (list hit the " + ISSUE_LIMIT + " cap — these totals are a floor)" : "") + "\n");

  if (!vendoredAt) {
    process.stdout.write("  could not date the vendored release, so which fixes are already in is unknown\n");
  } else if (candidates.length) {
    process.stdout.write("\nFIXED SINCE THE VENDORED RELEASE WAS CUT — check these, then adopt and cut:\n");
    candidates.forEach(function (i) {
      process.stdout.write("  #" + i.number + "  " + i.title.slice(0, 88) + "\n");
    });
    process.stdout.write("  Confirm each against the release notes before adopting: a closure date says\n");
    process.stdout.write("  when the issue was closed, not which release carries the commit.\n");
  } else {
    process.stdout.write("  none fixed since it was cut — nothing to adopt\n");
  }

  if (open.length) {
    process.stdout.write("\nstill open:\n");
    open.slice(0, 6).forEach(function (i) {
      process.stdout.write("  #" + i.number + "  " + i.title.slice(0, 88) + "\n");
    });
    if (open.length > 6) process.stdout.write("  … and " + (open.length - 6) + " more\n");
  }
  process.stdout.write("\n");
}

// The commit a release's tag points at, by date. This is the boundary that
// decides whether a fix is in that release: anything committed after it is not,
// however long the release object took to be created or published afterwards.
//
// Deliberately NOT `release view --json createdAt` — that is when the release
// OBJECT was made, which drifts from the tag whenever a release is drafted
// early or created late. On the release vendored here the two differ by twelve
// seconds; on a drafted one they differ by however long the draft sat.
//
// Null when it cannot be read; the caller then says the boundary is unknown
// rather than assuming a side.
function tagCommitDate(tag) {
  try {
    return run("gh", ["api", "repos/blamejs/blamejs/commits/" + tag,
      "--jq", ".commit.committer.date"]) || null;
  } catch (_e) { return null; }
}
function main() {
  var consumed = consumedPrimitives();
  var vendored = vendoredVersion();
  renderIssues(upstreamIssues(), tagCommitDate("v" + vendored));

  var tags, replay = process.argv[2] === "--assess";
  if (replay) {
    tags = process.argv.slice(3).filter(function (t) { return /^[\w.-]+$/.test(t); });
    if (!tags.length) {
      process.stderr.write("usage: blamejs-watch.js --assess <version>...\n");
      process.exit(2);
    }
  } else {
    try {
      tags = releasesSince(vendored);
    } catch (e) {
      process.stderr.write("could not list blamejs releases: " + e.message + "\n");
      process.exit(2);
    }
    if (!tags.length) {
      process.stderr.write("blamejs " + vendored + " is current — nothing published since.\n");
      return;
    }
  }

  var notable = 0;
  tags.forEach(function (t) {
    var a = assess(t, consumed);
    if (a.notable) {
      notable++;
      process.stdout.write(render(a, vendored) + "\n\n");
    } else {
      process.stderr.write("skipped " + a.tag + " (framework-internal): " + a.headline + "\n");
    }
  });

  if (notable) {
    process.stdout.write(notable + " of " + tags.length + " release(s)"
      + (replay ? "" : " since " + vendored) + " look worth a decision.\n");
  }

  if (fetchFailures) {
    process.stderr.write(fetchFailures + " release(s) could not be assessed — "
      + "this digest is incomplete.\n");
    process.exit(2);
  }
}

main();
