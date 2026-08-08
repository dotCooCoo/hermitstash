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
  "@noble/ciphers")
    # Browser ESM bundle only. The server side consumes blamejs's own
    # lib/vendor/noble-ciphers.cjs, so emitting a second CommonJS copy here
    # produced an orphan that nothing required and that showed up as a phantom
    # vendored artifact in the SBOM.
    echo 'export { xchacha20poly1305 } from "@noble/ciphers/chacha.js";' > _entry.mjs
    npx esbuild _entry.mjs --bundle --format=esm --minify --outfile=public/js/noble-ciphers.js --platform=browser
    rm _entry.mjs
    # Add header
    sed -i "1s|^|// XChaCha20-Poly1305 — vendored from @noble/ciphers v${INSTALLED_VER} by Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-ciphers\n// Bundled with esbuild. Exports: xchacha20poly1305\n|" public/js/noble-ciphers.js
    ;;

  "@noble/hashes")
    echo 'export { shake256 } from "@noble/hashes/sha3.js";' > _entry.mjs
    npx esbuild _entry.mjs --bundle --format=esm --minify --outfile=public/js/noble-hashes.js --platform=browser
    rm _entry.mjs
    sed -i "1s|^|// SHAKE256 — vendored from @noble/hashes v${INSTALLED_VER} by Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-hashes\n// Bundled with esbuild. Exports: shake256\n|" public/js/noble-hashes.js
    ;;

  "@noble/post-quantum")
    # Browser ESM bundle
    echo 'export { ml_kem512, ml_kem768, ml_kem1024 } from "@noble/post-quantum/ml-kem.js";' > _entry.mjs
    npx esbuild _entry.mjs --bundle --format=esm --minify --outfile=public/js/noble-pq.js --platform=browser
    rm _entry.mjs
    sed -i "1s|^|// ML-KEM — vendored from @noble/post-quantum v${INSTALLED_VER} by Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-post-quantum\n// Bundled with esbuild. Exports: ml_kem512, ml_kem768, ml_kem1024\n|" public/js/noble-pq.js
    # Server CJS bundle — convert ESM to CJS by replacing export statement.
    # INSTALLED_VER reaches the program via the environment so a version string
    # can never break out of the JS header literal.
    INSTALLED_VER="$INSTALLED_VER" node -e '
var fs = require("fs");
var src = fs.readFileSync("public/js/noble-pq.js", "utf8");
var exportMatch = src.match(/export\{([^}]+)\}/);
if (!exportMatch) { console.error("No export statement found"); process.exit(1); }
var mappings = exportMatch[1].split(",").map(function(s) {
  var parts = s.trim().split(" as ");
  return { local: parts[0].trim(), exported: parts[1].trim() };
});
var code = src.replace(/export\{[^}]+\};?\s*/, "");
var header = "// ML-KEM (FIPS 203) — vendored from @noble/post-quantum v" + process.env.INSTALLED_VER + " by Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-post-quantum\n// Converted from ESM to CJS for server-side use (hybrid ECIES key exchange)\n// Exports: ml_kem512, ml_kem768, ml_kem1024\n";
var exports = mappings.filter(function(m) { return m.exported.startsWith("ml_kem"); }).map(function(m) { return "  " + m.exported + ": " + m.local; }).join(",\n");
fs.writeFileSync("lib/vendor/noble-pq.cjs", header + code + "\nmodule.exports = {\n" + exports + "\n};\n");
console.log("Created lib/vendor/noble-pq.cjs");
'
    ;;

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
    # Sourced from GitHub at github.com/blamejs/blamejs (npm name is
    # taken by an unrelated package — vendor from source). Mirrors the
    # hermitstash-sync pattern: shallow clone of the release tag,
    # then drop .git so the vendored tree is a plain snapshot.
    #
    # VER may be "latest" (resolves to the latest GitHub Release tag)
    # or a specific tag like "v0.8.52" / "0.8.52".
    REPO_URL="https://github.com/blamejs/blamejs"
    if [ "$VER" = "latest" ]; then
      # Match check-blamejs-version.js: GitHub Releases API. GITHUB_TOKEN
      # used opportunistically for higher rate limits in CI (consumed
      # inside the inline node script below via process.env).
      TAG=$(node -e "
        var https = require('node:https');
        var opts = {
          headers: {
            'User-Agent': 'hermitstash-vendor-update',
            'Accept':     'application/vnd.github+json',
          },
        };
        if (process.env.GITHUB_TOKEN) opts.headers.Authorization = 'Bearer ' + process.env.GITHUB_TOKEN;
        https.get('https://api.github.com/repos/blamejs/blamejs/releases/latest', opts, function(res) {
          var c = [];
          res.on('data', function(b){ c.push(b); });
          res.on('end', function() {
            if (res.statusCode !== 200) { process.stderr.write('GitHub API HTTP ' + res.statusCode + '\n'); process.exit(2); }
            var p; try { p = JSON.parse(Buffer.concat(c).toString('utf8')); } catch (e) { process.stderr.write('bad JSON\n'); process.exit(2); }
            if (typeof p.tag_name !== 'string') { process.stderr.write('no tag_name\n'); process.exit(2); }
            process.stdout.write(p.tag_name);
          });
        }).on('error', function(e) { process.stderr.write(String(e) + '\n'); process.exit(2); });
      ")
    else
      # Allow user to pass either "0.8.52" or "v0.8.52".
      case "$VER" in v*) TAG="$VER" ;; *) TAG="v$VER" ;; esac
    fi
    INSTALLED_VER="${TAG#v}"
    echo "Resolved tag: $TAG (v$INSTALLED_VER)"

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
    node -e "var fs=require('fs'),p=require('path');fs.mkdirSync('$DEST',{recursive:true});for(var e of fs.readdirSync('$DEST')){fs.rmSync(p.join('$DEST',e),{recursive:true,force:true,maxRetries:60,retryDelay:300});}"

    # Shallow clone of the tag, then snapshot the working tree into
    # $DEST while filtering paths we never want vendored:
    #   - CLAUDE.md / .claude/   (project instructions / session settings)
    #   - examples/wiki/C\357\200\272/...   (Windows-mangled `C:` test artifact paths)
    TMPCLONE=".vendor-blamejs.tmp"
    # Clean up on ANY exit — including an early `exit 1` and the Windows+Dropbox
    # "Device or resource busy" lock that has aborted a run mid-script, leaving
    # MANIFEST un-updated. node's rmSync retries on EBUSY and the trap guarantees
    # the temp clone can't leak or abort the run before MANIFEST is written.
    _cleanup_tmpclone() { node -e "try{require('fs').rmSync('$TMPCLONE',{recursive:true,force:true,maxRetries:10,retryDelay:200})}catch(_e){}" 2>/dev/null || true; }
    trap _cleanup_tmpclone EXIT
    _cleanup_tmpclone
    git clone --depth 1 --branch "$TAG" "$REPO_URL" "$TMPCLONE"
    git -C "$TMPCLONE" archive HEAD | tar -x -C "$DEST" \
      --exclude='CLAUDE.md' \
      --exclude='.claude' \
      --exclude='.claude/*' \
      --exclude='examples/wiki/C*' \
      --exclude='.clusterfuzzlite' \
      --exclude='.clusterfuzzlite/*' \
      --exclude='oss-fuzz' \
      --exclude='oss-fuzz/*'
    _cleanup_tmpclone

    if [ ! -f "$DEST/package.json" ]; then
      echo "ERROR: extract failed — $DEST/package.json missing."
      exit 1
    fi

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
INSTALLED_VER="$INSTALLED_VER" PKG="$PKG" TAG="${TAG:-}" DATE="$DATE" MANIFEST="$MANIFEST" node -e '
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
