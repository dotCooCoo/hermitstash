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

function main() {
  var consumed = consumedPrimitives();
  var vendored = vendoredVersion();

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
