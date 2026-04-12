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
  for pkg in "@noble/ciphers" "@noble/hashes" "@noble/post-quantum" "@simplewebauthn/server" "argon2"; do
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
  for pkg in "@noble/ciphers" "@noble/hashes" "@noble/post-quantum" "@simplewebauthn/server" "argon2"; do
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

# Install temporarily
npm install "${PKG}@${VER}" --no-save --ignore-scripts 2>/dev/null
INSTALLED_VER=$(node -e "console.log(require('./node_modules/${PKG}/package.json').version)")
echo "Installed: $PKG@$INSTALLED_VER"

case "$PKG" in
  "@noble/ciphers")
    echo 'export { xchacha20poly1305 } from "@noble/ciphers/chacha.js";' > _entry.mjs
    npx esbuild _entry.mjs --bundle --format=esm --minify --outfile=public/js/noble-ciphers.js --platform=browser
    npx esbuild _entry.mjs --bundle --format=cjs --minify --outfile=lib/vendor/noble-ciphers.cjs --platform=node
    rm _entry.mjs
    # Add headers
    sed -i "1s|^|// XChaCha20-Poly1305 — vendored from @noble/ciphers v${INSTALLED_VER} by Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-ciphers\n// Bundled with esbuild. Exports: xchacha20poly1305\n|" public/js/noble-ciphers.js lib/vendor/noble-ciphers.cjs
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
    # Server CJS bundle — convert ESM to CJS by replacing export statement
    node -e "
var fs = require('fs');
var src = fs.readFileSync('public/js/noble-pq.js', 'utf8');
var exportMatch = src.match(/export\{([^}]+)\}/);
if (!exportMatch) { console.error('No export statement found'); process.exit(1); }
var mappings = exportMatch[1].split(',').map(function(s) {
  var parts = s.trim().split(' as ');
  return { local: parts[0].trim(), exported: parts[1].trim() };
});
var code = src.replace(/export\{[^}]+\};?\s*/, '');
var header = '// ML-KEM (FIPS 203) — vendored from @noble/post-quantum v${INSTALLED_VER} by Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-post-quantum\n// Converted from ESM to CJS for server-side use (hybrid ECIES key exchange)\n// Exports: ml_kem512, ml_kem768, ml_kem1024\n';
var exports = mappings.filter(function(m) { return m.exported.startsWith('ml_kem'); }).map(function(m) { return '  ' + m.exported + ': ' + m.local; }).join(',\n');
fs.writeFileSync('lib/vendor/noble-pq.cjs', header + code + '\nmodule.exports = {\n' + exports + '\n};\n');
console.log('Created lib/vendor/noble-pq.cjs');
"
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

  *)
    echo "Unknown package: $PKG"
    echo "Add a case to this script for bundling instructions."
    npm uninstall "$PKG" --no-save 2>/dev/null
    exit 1
    ;;
esac

# Update MANIFEST.json
node -e "
var fs = require('fs');
var m = JSON.parse(fs.readFileSync('$MANIFEST', 'utf8'));
var pkg = '$PKG';
if (m.packages[pkg]) {
  m.packages[pkg].version = '$INSTALLED_VER';
  m.packages[pkg].bundledAt = '$DATE';
  fs.writeFileSync('$MANIFEST', JSON.stringify(m, null, 2) + '\n');
  console.log('Updated MANIFEST.json: ' + pkg + ' → ' + '$INSTALLED_VER');
} else {
  console.log('Warning: ' + pkg + ' not in MANIFEST.json — add it manually');
}
"

# Remove npm package
npm uninstall "$PKG" --no-save 2>/dev/null || true

# Verify bundle is self-contained (no unresolved requires after npm removal)
echo ""
echo "=== Verifying bundle integrity ==="
node -e "
var files = require('./$MANIFEST').packages['$PKG'].files || {};
var ok = true;
Object.values(files).forEach(function(f) {
  if (typeof f !== 'string' || !f.endsWith('.cjs')) return;
  try { require('./' + f); console.log('  ' + f + ': OK'); }
  catch(e) { console.log('  ' + f + ': FAIL — ' + e.message); ok = false; }
});
if (!ok) { console.log('ERROR: Bundle has unresolved dependencies!'); process.exit(1); }
" || { echo "Bundle verification failed! Do not commit."; exit 1; }

# Show what changed
echo ""
echo "=== Git diff summary ==="
git diff --stat lib/vendor/ public/js/ 2>/dev/null || true
echo ""

# Show file size changes
echo "=== Bundle sizes ==="
node -e "
var fs = require('fs');
var m = JSON.parse(fs.readFileSync('$MANIFEST', 'utf8'));
var pkg = m.packages['$PKG'];
if (!pkg) process.exit();
var files = pkg.files || {};
Object.keys(files).forEach(function(role) {
  var f = files[role];
  if (typeof f !== 'string') return;
  try {
    var stat = fs.statSync(f);
    console.log('  ' + f + ': ' + (stat.size / 1024).toFixed(1) + ' KB');
  } catch(e) {}
});
"

echo ""
echo "=== Done: $PKG v$INSTALLED_VER vendored ==="
echo ""
echo "Next steps:"
echo "  1. Review:  git diff lib/vendor/ public/js/"
echo "  2. Verify:  node server.js"
echo "  3. Test:    cd tests && npm test"
echo "  4. Commit:  git add lib/vendor/ public/js/ && git commit -m 'Vendor $PKG@$INSTALLED_VER'"
