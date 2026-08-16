#!/usr/bin/env bash
# vendor-update.sh — Update a vendored dependency
#
# Usage:
#   ./scripts/vendor-update.sh <package-name> [version]
#
# Examples:
#   ./scripts/vendor-update.sh @noble/ciphers          # latest
#   ./scripts/vendor-update.sh @noble/ciphers 2.2.0    # specific version
#   ./scripts/vendor-update.sh argon2 0.45.0
#   ./scripts/vendor-update.sh @simplewebauthn/server
#   ./scripts/vendor-update.sh --check                 # check for updates
#   ./scripts/vendor-update.sh --diff @noble/ciphers   # show changelog between vendored and latest
#   ./scripts/vendor-update.sh --diff-all              # show changelog for all outdated packages
#
# What it does:
#   1. Installs the package temporarily via npm
#   2. Bundles with esbuild (CJS for server, ESM for browser)
#   3. Copies native prebuilds if applicable (argon2)
#   4. Updates MANIFEST.json with new version and date
#   5. Removes the npm package
#   6. Shows git diff of changed vendor files
#
# After running, manually verify with: node server.js
# Then commit: git add lib/vendor/ public/js/ && git commit

set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST="lib/vendor/MANIFEST.json"
DATE=$(date +%Y-%m-%d)

# ---- Helper: get vendored version for a package ----
get_vendored_ver() {
  node -e "var m=require('./$MANIFEST'); var p=m.packages['$1']; console.log(p?p.version:'?')"
}

# ---- Helper: packages this script can check against the npm registry ----
# Derived from MANIFEST.json rather than hardcoded, so the list cannot drift
# away from what is actually vendored. blamejs is excluded: it is pinned to a
# GitHub release tag, not an npm version, and has its own currency gate
# (`node scripts/release.js vendor`).
#
# The previous hardcoded list had drifted badly — it still named argon2 (now
# Node's built-in crypto.argon2, not vendored at all) and @simplewebauthn/server
# (now nested inside blamejs, not a top-level package), while omitting the three
# browser bundles that ARE vendored here. Every row it printed for them read "?",
# so the one genuinely stale bundle was indistinguishable from the noise.
npm_checkable_pkgs() {
  node -e "var m=require('./$MANIFEST'); console.log(Object.keys(m.packages||{}).filter(function (k) { return k !== 'blamejs'; }).join('\n'))"
}

# ---- Helper: show changelog/diff between vendored and latest for one package ----
show_pkg_diff() {
  local pkg="$1"
  local vendored latest repo
  vendored=$(get_vendored_ver "$pkg")
  latest=$(npm view "$pkg" version 2>/dev/null || echo "?")

  if [ "$vendored" = "$latest" ]; then
    echo "$pkg: v$vendored — already up to date"
    return
  fi

  repo=$(node -e "var m=require('./$MANIFEST'); var p=m.packages['$1']; console.log(p&&p.source?p.source:'')")

  echo ""
  echo "━━━ $pkg: v$vendored → v$latest ━━━"
  echo ""

  # Show npm changelog (versions between vendored and latest)
  echo "Published versions since v$vendored:"
  npm view "$pkg" versions --json 2>/dev/null | node -e "
    var versions = JSON.parse(require('fs').readFileSync(0,'utf8'));
    if (!Array.isArray(versions)) versions = [versions];
    var found = false;
    versions.forEach(function(v) {
      if (v === '$vendored') found = true;
      else if (found) console.log('  ' + v);
    });
  " 2>/dev/null || echo "  (could not fetch version list)"

  # Show npm dist info for latest
  echo ""
  echo "Latest (v$latest):"
  npm view "$pkg@$latest" dist.tarball dist.unpackedSize 2>/dev/null | while read -r line; do
    echo "  $line"
  done

  # Show changelog URL if available
  if [ -n "$repo" ]; then
    echo ""
    echo "Changelog: $repo/releases"
    echo "Compare:   $repo/compare/v${vendored}...v${latest}"
  fi
  echo ""
}

# ---- Check mode: show outdated packages ----
if [ "${1:-}" = "--check" ]; then
  echo "Checking vendored package versions..."
  echo ""
  printf "%-30s %-12s %-12s %-14s %s\n" "Package" "Vendored" "Latest" "Bundled" "Status"
  printf "%-30s %-12s %-12s %-14s %s\n" "-------" "--------" "------" "-------" "------"
  for pkg in $(npm_checkable_pkgs); do
    vendored=$(get_vendored_ver "$pkg")
    bundled=$(node -e "var m=require('./$MANIFEST'); var p=m.packages['$pkg']; console.log(p&&p.bundledAt?p.bundledAt:'?')")
    latest=$(npm view "$pkg" version 2>/dev/null || echo "?")
    if [ "$vendored" = "$latest" ]; then
      status="up to date"
    else
      status="UPDATE AVAILABLE"
    fi
    printf "%-30s %-12s %-12s %-14s %s\n" "$pkg" "$vendored" "$latest" "$bundled" "$status"
  done
  exit 0
fi

# ---- Diff mode: show changelog for one package ----
if [ "${1:-}" = "--diff" ]; then
  PKG="${2:?Usage: vendor-update.sh --diff <package-name>}"
  show_pkg_diff "$PKG"
  exit 0
fi

# ---- Diff-all mode: show changelog for all outdated packages ----
if [ "${1:-}" = "--diff-all" ]; then
  any_outdated=false
  for pkg in $(npm_checkable_pkgs); do
    vendored=$(get_vendored_ver "$pkg")
    latest=$(npm view "$pkg" version 2>/dev/null || echo "?")
    if [ "$vendored" != "$latest" ]; then
      show_pkg_diff "$pkg"
      any_outdated=true
    fi
  done
  if [ "$any_outdated" = false ]; then
    echo "All vendored packages are up to date."
  fi
  exit 0
fi

# ---- Update mode ----
PKG="${1:?Usage: vendor-update.sh <package-name> [version]}"
VER="${2:-latest}"

echo "=== Vendoring $PKG@$VER ==="

# Install temporarily (skipped for blamejs, which is sourced from the sibling
# working tree / GitHub release tag, not npm).
if [ "$PKG" != "blamejs" ]; then
  npm install "${PKG}@${VER}" --no-save --ignore-scripts 2>/dev/null
  INSTALLED_VER=$(node -e "console.log(require('./node_modules/${PKG}/package.json').version)")
  echo "Installed: $PKG@$INSTALLED_VER"
fi

case "$PKG" in
  # @noble/ciphers, @noble/hashes and @noble/post-quantum are NOT vendored here
  # any more. Each used to be installed from npm and bundled with esbuild into
  # public/js/, alongside the copy blamejs vendors for the server — two builds
  # of one upstream package, resolved separately, versioned separately and
  # carried separately in the SBOM. They drifted, which is exactly what that
  # arrangement invites: a framework bump moved the server halves and left the
  # browser halves on the previous release, and every documentation reference
  # still agreed with whichever half it happened to name.
  #
  # blamejs now publishes browser builds of the same primitives, so the browser
  # assets are copied out of the vendored framework by the blamejs case below.
  # One upstream source, one version, one refresh — there is no second copy left
  # to drift. Do not reintroduce a per-package case for these.

  "@simplewebauthn/server")
    echo "module.exports = require(\"@simplewebauthn/server\");" > _entry.cjs
    npx esbuild _entry.cjs --bundle --format=cjs --platform=node --minify --outfile=lib/vendor/simplewebauthn-server.cjs --external:crypto --external:node:crypto
    rm _entry.cjs
    sed -i "1s|^|// @simplewebauthn/server v${INSTALLED_VER} — vendored. License: MIT\n// https://github.com/MasterKale/SimpleWebAuthn\n|" lib/vendor/simplewebauthn-server.cjs
    ;;

  "argon2")
    # argon2 needs special handling: bundle JS + copy native prebuilds
    npm install "${PKG}@${VER}" --no-save 2>/dev/null  # re-install with scripts for prebuilds
    echo "module.exports = require(\"argon2\");" > _entry.cjs
    npx esbuild _entry.cjs --bundle --format=cjs --platform=node --outfile=lib/vendor/argon2/argon2.cjs
    rm _entry.cjs
    # Copy fresh prebuilds
    rm -rf lib/vendor/argon2/prebuilds
    cp -r node_modules/argon2/prebuilds lib/vendor/argon2/prebuilds
    ;;

  "blamejs")
    # Sourced from the npm registry as @blamejs/core.
    #
    # The bare name `blamejs` on npm belongs to an UNRELATED package — never
    # install it. Only the scoped @blamejs/core is this framework.
    #
    # Why the registry rather than a git clone of the release tag: the tarball
    # carries a published sha512 integrity value, a registry signature, and a
    # SLSA provenance attestation, so the bytes that land in lib/vendor/ can be
    # checked against something. A shallow clone verifies nothing at all — it
    # trusts whatever the tag points at, at the moment it is fetched. For a
    # project that publishes provenance for its own artifacts, its single most
    # security-critical dependency should not arrive unverified.
    #
    # The tarball is also byte-for-byte what upstream published. Cloning on a
    # machine with core.autocrlf=true rewrites every line ending on checkout,
    # so the vendored tree could never be compared against upstream.
    #
    # VER may be "latest" (resolves to the current published version) or an
    # explicit version, with or without a leading v ("0.18.16" / "v0.18.16").
    NPM_NAME="@blamejs/core"
    if [ "$VER" = "latest" ]; then
      INSTALLED_VER=$(npm view "$NPM_NAME" version 2>/dev/null)
      if [ -z "$INSTALLED_VER" ]; then
        echo "ERROR: could not resolve the latest $NPM_NAME version from the registry."
        exit 1
      fi
    else
      INSTALLED_VER="${VER#v}"
    fi
    # The git tag is still recorded in MANIFEST: it is the handle the release
    # runner's freshness gate uses, and the handle for fetching the few files
    # the published tarball does not carry (upstream's own lint gate, which the
    # patterns advisory reads).
    TAG="v$INSTALLED_VER"
    echo "Resolved $NPM_NAME@$INSTALLED_VER (tag $TAG)"

    DEST="lib/vendor/blamejs"
    # Empty $DEST's CONTENTS rather than removing $DEST itself. On Windows+Dropbox
    # the sync client holds the directory handle open, so the recursive rmSync's
    # final rmdir of $DEST fails with EPERM even after every child is gone —
    # aborting the run with the tree half-gutted (a git restore is then needed).
    # Deleting each child (with retries to ride out the transient EBUSY/EPERM a
    # file-syncing agent plants) and LEAVING the directory in place sidesteps that
    # rmdir: the tar extract below writes the new tree straight into the kept dir.
    # Cross-platform + tolerant of Windows-mangled paths like "C\357\200\272"
    # (U+F03A); a no-op-safe wipe on a clean checkout (empty dir → nothing to do).
    # Leaving the TOP directory alone was not enough: removing a child
    # directory recursively still ends in an rmdir of that child, so a lock one
    # level down (lib/) killed the run exactly the same way. scripts/_vendor-wipe.js
    # falls back to emptying a held directory instead of removing it, and fails
    # loudly if a FILE survives — extracting over leftover files would mix two
    # releases, which is worse than stopping.
    node scripts/_vendor-wipe.js "$DEST"

    # Fetch the published tarball, verify its bytes against the integrity value
    # the registry advertises, then unpack it into $DEST.
    #
    # The published package contains only what is actually consumed — index.js,
    # lib/ (including the nested vendor bundles and their MANIFEST), bin/ and
    # the licence files. The repository's examples/, docs/, bench/, fuzz/ and
    # test/ trees are not published, so the exclusion list the clone needed is
    # gone with them: there is no CLAUDE.md, no .claude/, no oss-fuzz/, and none
    # of the Windows-mangled `examples/wiki/C:` paths to filter out. The
    # leaked-path guard below still runs, so their return would be caught rather
    # than assumed impossible.
    TMPPACK=".vendor-blamejs.tmp"
    # Clean up on ANY exit — including an early `exit 1` and the Windows+Dropbox
    # "Device or resource busy" lock that has aborted a run mid-script, leaving
    # MANIFEST un-updated. node's rmSync retries on EBUSY and the trap guarantees
    # the temp directory can't leak or abort the run before MANIFEST is written.
    _cleanup_tmppack() { node -e "try{require('fs').rmSync('$TMPPACK',{recursive:true,force:true,maxRetries:10,retryDelay:200})}catch(_e){}" 2>/dev/null || true; }
    trap _cleanup_tmppack EXIT
    _cleanup_tmppack
    mkdir -p "$TMPPACK"

    # The integrity value is read BEFORE the download so the comparison is
    # against what the registry publishes, not against the file just received.
    INTEGRITY=$(npm view "$NPM_NAME@$INSTALLED_VER" dist.integrity 2>/dev/null)
    if [ -z "$INTEGRITY" ]; then
      echo "ERROR: registry published no integrity value for $NPM_NAME@$INSTALLED_VER."
      echo "       Refusing to vendor bytes that cannot be checked."
      exit 1
    fi

    npm pack "$NPM_NAME@$INSTALLED_VER" --pack-destination "$TMPPACK" --silent >/dev/null 2>&1
    TARBALL=$(node -e "
      var fs=require('fs'),p=require('path');
      var d=process.argv[1];
      var f=fs.readdirSync(d).filter(function(n){return /\.tgz\$/.test(n);});
      if(f.length!==1){process.stderr.write('expected exactly one tarball, found '+f.length+'\n');process.exit(1);}
      process.stdout.write(p.join(d,f[0]));
    " "$TMPPACK")
    if [ -z "$TARBALL" ] || [ ! -f "$TARBALL" ]; then
      echo "ERROR: npm pack produced no tarball for $NPM_NAME@$INSTALLED_VER."
      exit 1
    fi

    # Recompute the digest over the received bytes and compare. A mismatch means
    # the tarball is not what the registry says it published, so the run stops
    # here rather than unpacking it.
    INTEGRITY="$INTEGRITY" TARBALL="$TARBALL" node -e '
      var fs = require("fs"), crypto = require("crypto");
      var want = process.env.INTEGRITY.trim();
      var m = /^sha(256|384|512)-(.+)$/.exec(want);
      if (!m) { console.error("unrecognized integrity format: " + want); process.exit(1); }
      var got = "sha" + m[1] + "-" + crypto.createHash("sha" + m[1])
        .update(fs.readFileSync(process.env.TARBALL)).digest("base64");
      if (got !== want) {
        console.error("INTEGRITY MISMATCH");
        console.error("  published: " + want);
        console.error("  received:  " + got);
        process.exit(1);
      }
      console.log("Integrity verified: " + want.slice(0, 24) + "…");
    '

    # --strip-components=1 drops the tarball's leading package/ directory.
    tar -xzf "$TARBALL" -C "$DEST" --strip-components=1
    _cleanup_tmppack

    # Upstream's own codebase-patterns lint gate lives in its test tree, which
    # is not part of the published package. The release runner's patterns
    # advisory compares our gate against it to surface detector classes worth
    # adopting, so it is fetched separately and kept OUTSIDE lib/vendor/ — that
    # directory holds exactly the bytes the integrity check above covered, and
    # mixing in a file from a different source would make that claim untrue.
    #
    # Pinned to the same tag as the package, so the snapshot and the vendored
    # tree always describe the same release. Failing here rather than skipping:
    # a silently missing snapshot turns the advisory into a check that reports
    # nothing while looking like it passed.
    PATTERNS_SNAPSHOT="tests/lint/blamejs-codebase-patterns.snapshot.js"
    PATTERNS_URL="https://raw.githubusercontent.com/blamejs/blamejs/$TAG/test/layer-0-primitives/codebase-patterns.test.js"
    mkdir -p "$(dirname "$PATTERNS_SNAPSHOT")"
    if ! curl -fsSL --retry 3 --max-time 60 "$PATTERNS_URL" -o "$PATTERNS_SNAPSHOT"; then
      echo "ERROR: could not fetch upstream's codebase-patterns gate for $TAG."
      echo "       URL: $PATTERNS_URL"
      echo "       The patterns advisory reads this; refusing to leave it stale."
      exit 1
    fi
    echo "Snapshotted upstream patterns gate for $TAG ($(wc -c < "$PATTERNS_SNAPSHOT") bytes)"

    if [ ! -f "$DEST/package.json" ]; then
      echo "ERROR: extract failed — $DEST/package.json missing."
      exit 1
    fi

    # Browser crypto assets. The pages import these over HTTP from /js/, so
    # they have to live under public/ — but they are COPIES of the framework's
    # own browser builds, not a second build of the same upstream packages.
    # That distinction is the point: the version, the bytes and the refresh all
    # come from one place, so the browser half cannot fall behind the server
    # half the way it did when each was vendored independently.
    #
    # Named per destination because the page URLs predate this and are not
    # worth churning: noble-post-quantum ships as /js/noble-pq.js.
    BROWSER_SRC="$DEST/lib/vendor/browser"
    if [ ! -d "$BROWSER_SRC" ]; then
      echo "ERROR: $BROWSER_SRC missing — this blamejs release ships no browser builds."
      echo "       Either the release regressed or the layout moved; do not fall back to"
      echo "       bundling these from npm again without deciding to re-split them."
      exit 1
    fi
    for pair in "noble-ciphers:noble-ciphers" "noble-hashes:noble-hashes" "noble-post-quantum:noble-pq"; do
      src="${pair%%:*}"; dst="${pair##*:}"
      if [ ! -f "$BROWSER_SRC/$src.mjs" ]; then
        echo "ERROR: $BROWSER_SRC/$src.mjs missing from the vendored framework."
        exit 1
      fi
      cp "$BROWSER_SRC/$src.mjs" "public/js/$dst.js"
      echo "  browser asset: public/js/$dst.js  <- blamejs lib/vendor/browser/$src.mjs"
    done

    # The SBOM still needs the public/js path to name a package and a version —
    # a scanner reads what ships, and these files ship. Take that version from
    # the framework's own manifest rather than restating it, so the entry cannot
    # disagree with the bytes it describes. Restating it is what produced the
    # earlier split, where the recorded browser version stayed on the previous
    # release for two refreshes while the file itself had moved.
    DEST="$DEST" node -e '
      var fs = require("fs");
      var dest = process.env.DEST;
      var manifestPath = "lib/vendor/MANIFEST.json";
      var m = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      var nested = JSON.parse(fs.readFileSync(dest + "/lib/vendor/MANIFEST.json", "utf8"));
      var today = new Date().toISOString().slice(0, 10);
      ["@noble/ciphers", "@noble/hashes", "@noble/post-quantum"].forEach(function (name) {
        var ours = m.packages[name];
        var theirs = nested.packages && nested.packages[name];
        if (!ours) return;
        if (!theirs || typeof theirs.version !== "string") {
          console.error("ERROR: " + name + " has no version in the framework manifest — refusing to guess.");
          process.exit(1);
        }
        ours.version = theirs.version;
        if (typeof ours.cpe === "string") {
          // Replacement function rather than a capture-group template: this
          // program is embedded in a single-quoted shell string, where anything
          // written as a dollar reference reads to shellcheck as an expansion
          // that will silently not expand.
          ours.cpe = ours.cpe.replace(/^(cpe:2\.3:a:[^:]+:[^:]+:)[^:]+/, function (whole, prefix) {
            return prefix + theirs.version;
          });
        }
        ours.bundledAt = today;
      });
      fs.writeFileSync(manifestPath, JSON.stringify(m, null, 2) + "\n");
      console.log("  browser package versions synced from the framework manifest");
    '

    # Surface guard + leaked-path guard.
    node -e "var b=require('./$DEST');console.log('blamejs surface OK:',Object.keys(b).length,'primitives');"
    if find "$DEST" -iname 'CLAUDE.md' -o -iname '.claude' -o -name 'C[\\:]*' 2>/dev/null | grep -q .; then
      echo "ERROR: filtered paths leaked through — investigate the exclude list."
      find "$DEST" -iname 'CLAUDE.md' -o -iname '.claude' -o -name 'C[\\:]*' 2>/dev/null | head -20
      exit 1
    fi

    # The tag is written together with version + bundledAt in the single
    # MANIFEST update below (one read-modify-write), so a mid-write failure
    # can't leave the tag and version disagreeing (which would false-trip the
    # CI freshness gate). The tag handle mirrors hermitstash-sync's MANIFEST.
    ;;

  *)
    echo "Unknown package: $PKG"
    echo "Add a case to this script for bundling instructions."
    npm uninstall "$PKG" --no-save 2>/dev/null
    exit 1
    ;;
esac

# Update MANIFEST.json
# Pass the resolved values through the environment, never spliced into the JS
# source — a quote- or newline-bearing tag is then inert data, not code.
#
# TAG defaults to empty: it is only set on the blamejs path (a GitHub release
# tag). Under `set -u` the bare "$TAG" aborted this step for every other
# package, so a browser-bundle refresh rebuilt the artifact and then died
# BEFORE recording the new version — leaving the manifest permanently claiming
# the old one. That is silent drift by construction, and it is why the vendored
# browser bundles sat unrecorded.
INSTALLED_VER="$INSTALLED_VER" PKG="$PKG" TAG="${TAG:-}" DATE="$DATE" MANIFEST="$MANIFEST" INTEGRITY="${INTEGRITY:-}" node -e '
var fs = require("fs");
var manifestPath = process.env.MANIFEST;
var m = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
var pkg = process.env.PKG;
if (m.packages[pkg]) {
  var entry = m.packages[pkg];
  var prev = entry.version;
  entry.version = process.env.INSTALLED_VER;
  entry.bundledAt = process.env.DATE;
  if (pkg === "blamejs" && process.env.TAG) entry.tag = process.env.TAG;
  // The registry-published digest of the exact tarball this tree was unpacked
  // from. Recorded so the vendored bytes stay traceable to something after the
  // fact — the tree itself carries no proof of where it came from, and a plain
  // version string is a claim rather than evidence.
  if (process.env.INTEGRITY) entry.integrity = process.env.INTEGRITY.trim();
  // Re-stamp the CPE version field. Trivy / Grype match CVEs against the CPE,
  // so leaving it at the previous version silently scans the wrong release —
  // the bump would look applied while vulnerability matching still targeted
  // the version that was just replaced. Only the version component is
  // rewritten; the rest of the CPE is left exactly as authored.
  if (typeof entry.cpe === "string" && prev) {
    var parts = entry.cpe.split(":");
    // cpe:2.3:a:<vendor>:<product>:<version>:...  -> index 5 is the version
    if (parts.length > 5 && parts[5] === prev) {
      parts[5] = process.env.INSTALLED_VER;
      entry.cpe = parts.join(":");
    }
  }
  fs.writeFileSync(manifestPath, JSON.stringify(m, null, 2) + "\n");
  console.log("Updated MANIFEST.json: " + pkg + " → " + process.env.INSTALLED_VER);
} else {
  console.log("Warning: " + pkg + " not in MANIFEST.json — add it manually");
}
'

# Project the vendored blamejs tree's own dependency manifest into the
# top-level SBOM (packages.blamejs.components) so Trivy / Grype scan an
# accurate, complete inventory. blamejs bumps that bundle a nested version or
# add a bundled package; this keeps the top-level mirror in lock-step with what
# is actually on disk instead of relying on a hand-edit that silently drifts.
if [ "$PKG" = "blamejs" ]; then
  node scripts/refresh-blamejs-sbom.js
fi

# Remove npm package
npm uninstall "$PKG" --no-save 2>/dev/null || true

# Verify bundle is self-contained (no unresolved requires after npm removal)
echo ""
echo "=== Verifying bundle integrity ==="
PKG="$PKG" MANIFEST="$MANIFEST" node -e '
var fs = require("fs");
var path = require("path");
var m = JSON.parse(fs.readFileSync(process.env.MANIFEST, "utf8"));
var files = (m.packages[process.env.PKG] || {}).files || {};
var ok = true;
Object.values(files).forEach(function(f) {
  if (typeof f !== "string" || !f.endsWith(".cjs")) return;
  try { require(path.resolve(f)); console.log("  " + f + ": OK"); }
  catch(e) { console.log("  " + f + ": FAIL — " + e.message); ok = false; }
});
if (!ok) { console.log("ERROR: Bundle has unresolved dependencies!"); process.exit(1); }
' || { echo "Bundle verification failed! Do not commit."; exit 1; }

# Show what changed
echo ""
echo "=== Git diff summary ==="
git diff --stat lib/vendor/ public/js/ 2>/dev/null || true
echo ""

# Show file size changes
echo "=== Bundle sizes ==="
PKG="$PKG" MANIFEST="$MANIFEST" node -e '
var fs = require("fs");
var m = JSON.parse(fs.readFileSync(process.env.MANIFEST, "utf8"));
var pkg = m.packages[process.env.PKG];
if (!pkg) process.exit();
var files = pkg.files || {};
Object.keys(files).forEach(function(role) {
  var f = files[role];
  if (typeof f !== "string") return;
  try {
    var stat = fs.statSync(f);
    console.log("  " + f + ": " + (stat.size / 1024).toFixed(1) + " KB");
  } catch(e) {}
});
'

echo ""
echo "=== Done: $PKG v$INSTALLED_VER vendored ==="
echo ""
echo "Next steps:"
echo "  1. Review:  git diff lib/vendor/ public/js/"
echo "  2. Verify:  node server.js"
echo "  3. Test:    cd tests && npm test"
echo "  4. Commit:  git add lib/vendor/ public/js/ && git commit -m 'Vendor $PKG@$INSTALLED_VER'"
