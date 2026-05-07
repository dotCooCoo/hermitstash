#!/usr/bin/env bash
# vendor-update.sh — update a vendored dependency in lib/vendor/
#
# Usage:
#   ./scripts/vendor-update.sh <package> [version]    # bundle (default: latest)
#   ./scripts/vendor-update.sh --check                # show outdated vendored packages
#   ./scripts/vendor-update.sh --diff <package>       # show vendored vs latest + changelog url
#   ./scripts/vendor-update.sh --diff-all             # diff every outdated package
#
# What it does:
#   1. installs the package(s) temporarily via npm
#   2. bundles with esbuild (CJS, server-side)
#   3. copies native prebuilds where applicable (argon2)
#   4. updates lib/vendor/MANIFEST.json (version + bundledAt)
#   5. removes the temporarily-installed npm package
#   6. require()s the bundle to verify it has no unresolved imports
#
# After running:
#   node test/smoke.js          # framework checks
#   cd examples/wiki && rm -rf data data-e2e && node test/e2e.js   # wiki e2e
#
# Adding a new package: extend the case statement near the bottom.

set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST="lib/vendor/MANIFEST.json"
DATE=$(date +%Y-%m-%d)

# Packages we vendor — kept in sync with MANIFEST.json. Used by --check
# and --diff-all to know which entries to walk.
VENDORED_PACKAGES=("@noble/ciphers" "@noble/post-quantum" "@simplewebauthn/server" "argon2" "peculiar-pki")

get_vendored_ver() {
  node -e "var m=require('./$MANIFEST'); var p=m.packages['$1']; console.log(p?p.version:'?')"
}

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
  echo "=== $pkg: v$vendored -> v$latest ==="
  echo ""
  echo "Versions published since v$vendored:"
  npm view "$pkg" versions --json 2>/dev/null | node -e "
    var versions = JSON.parse(require('fs').readFileSync(0,'utf8'));
    if (!Array.isArray(versions)) versions = [versions];
    var found = false;
    versions.forEach(function(v) {
      if (v === '$vendored') found = true;
      else if (found) console.log('  ' + v);
    });
  " 2>/dev/null || echo "  (could not fetch version list)"

  if [ -n "$repo" ]; then
    echo ""
    echo "Changelog: $repo/releases"
    echo "Compare:   $repo/compare/v${vendored}...v${latest}"
  fi
  echo ""
}

if [ "${1:-}" = "--check" ]; then
  echo "Checking vendored package versions..."
  echo ""
  printf "%-30s %-15s %-15s %-12s %s\n" "Package" "Vendored" "Latest" "Bundled" "Status"
  printf "%-30s %-15s %-15s %-12s %s\n" "-------" "--------" "------" "-------" "------"
  for pkg in "${VENDORED_PACKAGES[@]}"; do
    vendored=$(get_vendored_ver "$pkg")
    bundled=$(node -e "var m=require('./$MANIFEST'); var p=m.packages['$pkg']; console.log(p&&p.bundledAt?p.bundledAt:'?')")
    if [ "$pkg" = "peculiar-pki" ]; then
      latest="meta-bundle"
      status="check x509+pkijs separately"
    else
      latest=$(npm view "$pkg" version 2>/dev/null || echo "?")
      if [ "$vendored" = "$latest" ]; then status="up to date"; else status="UPDATE AVAILABLE"; fi
    fi
    printf "%-30s %-15s %-15s %-12s %s\n" "$pkg" "$vendored" "$latest" "$bundled" "$status"
  done
  exit 0
fi

if [ "${1:-}" = "--diff" ]; then
  PKG="${2:?Usage: vendor-update.sh --diff <package>}"
  show_pkg_diff "$PKG"
  exit 0
fi

if [ "${1:-}" = "--diff-all" ]; then
  any=false
  for pkg in "${VENDORED_PACKAGES[@]}"; do
    [ "$pkg" = "peculiar-pki" ] && continue
    vendored=$(get_vendored_ver "$pkg")
    latest=$(npm view "$pkg" version 2>/dev/null || echo "?")
    if [ "$vendored" != "$latest" ]; then
      show_pkg_diff "$pkg"
      any=true
    fi
  done
  [ "$any" = false ] && echo "All vendored packages are up to date."
  exit 0
fi

# ---- update mode ----
PKG="${1:?Usage: vendor-update.sh <package> [version]}"
VER="${2:-latest}"

echo "=== Vendoring $PKG@$VER ==="

if [ "$PKG" != "peculiar-pki" ]; then
  npm install "${PKG}@${VER}" --no-save --ignore-scripts 2>/dev/null
  INSTALLED_VER=$(node -e "console.log(require('./node_modules/${PKG}/package.json').version)")
  echo "Installed: $PKG@$INSTALLED_VER"
fi

case "$PKG" in
  "@noble/ciphers")
    echo 'export { xchacha20poly1305 } from "@noble/ciphers/chacha.js";' > _entry.mjs
    npx esbuild _entry.mjs --bundle --format=cjs --minify --platform=node --outfile=lib/vendor/noble-ciphers.cjs
    rm _entry.mjs
    sed -i "1s|^|// XChaCha20-Poly1305 — vendored from @noble/ciphers v${INSTALLED_VER} by Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-ciphers\n// Bundled with esbuild. Exports: xchacha20poly1305\n|" lib/vendor/noble-ciphers.cjs
    ;;

  "@noble/post-quantum")
    cat > _entry.mjs <<'ENTRY'
export { ml_kem512, ml_kem768, ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
export { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
export { slh_dsa_sha2_128f, slh_dsa_sha2_192f, slh_dsa_sha2_256f, slh_dsa_shake_128f, slh_dsa_shake_192f, slh_dsa_shake_256f } from "@noble/post-quantum/slh-dsa.js";
ENTRY
    npx esbuild _entry.mjs --bundle --format=cjs --minify --platform=node --outfile=lib/vendor/noble-post-quantum.cjs
    rm _entry.mjs
    sed -i "1s|^|// @noble/post-quantum v${INSTALLED_VER} — vendored from Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-post-quantum\n// Bundled with esbuild. Exports: ml_kem512 / ml_kem768 / ml_kem1024 (FIPS 203 KEM),\n//   ml_dsa44 / ml_dsa65 / ml_dsa87 (FIPS 204 lattice signatures),\n//   slh_dsa_sha2_*f / slh_dsa_shake_*f (FIPS 205 hash signatures).\n|" lib/vendor/noble-post-quantum.cjs
    ;;

  "@simplewebauthn/server")
    echo "module.exports = require(\"@simplewebauthn/server\");" > _entry.cjs
    npx esbuild _entry.cjs --bundle --format=cjs --platform=node --minify --external:crypto --external:node:crypto --outfile=lib/vendor/simplewebauthn-server.cjs
    rm _entry.cjs
    sed -i "1s|^|// @simplewebauthn/server v${INSTALLED_VER} — vendored. License: MIT\n// https://github.com/MasterKale/SimpleWebAuthn\n|" lib/vendor/simplewebauthn-server.cjs
    ;;

  "argon2")
    echo "ERROR: argon2 is no longer vendored. The framework uses Node's built-in"
    echo "       crypto.argon2* (Node 24+) via lib/argon2-builtin.js. Operators"
    echo "       wanting to override pass an alternative argon2 impl through"
    echo "       opts to b.auth.password.{hash,verify,needsRehash}."
    exit 1
    ;;

  "peculiar-pki")
    # Meta-bundle: @peculiar/x509 + pkijs + reflect-metadata + every transitive
    # ASN.1 schema package, packed into one CJS file. lib/mtls-ca.js loads the
    # bundle via the default engine in lib/mtls-engine-default.js for CA gen,
    # client-cert signing, and PKCS#12 packaging — no openssl CLI at runtime.
    npm install --no-save --ignore-scripts \
      reflect-metadata \
      pvutils pvtsutils asn1js \
      "@peculiar/asn1-schema" "@peculiar/asn1-x509" "@peculiar/asn1-ecc" "@peculiar/asn1-rsa" \
      "@peculiar/x509" pkijs 2>/dev/null
    X509_VER=$(node -e "console.log(require('./node_modules/@peculiar/x509/package.json').version)")
    PKIJS_VER=$(node -e "console.log(require('./node_modules/pkijs/package.json').version)")
    echo "Installed: @peculiar/x509@$X509_VER, pkijs@$PKIJS_VER"
    cat > _pki-entry.mjs <<'ENTRY'
// reflect-metadata polyfills Reflect.metadata / defineMetadata / getMetadata.
// @peculiar/asn1-schema's TypeScript decorators emit calls into these at
// runtime, so the polyfill must load first via side-effect import.
import "reflect-metadata";
import * as pkijsLib from "pkijs";
import * as x509Lib from "@peculiar/x509";
import { webcrypto } from "node:crypto";
const engine = new pkijsLib.CryptoEngine({ name: "node", crypto: webcrypto, subtle: webcrypto.subtle });
pkijsLib.setEngine("node", engine);
x509Lib.cryptoProvider.set(webcrypto);
export const pkijs = pkijsLib;
export const x509 = x509Lib;
export const crypto = webcrypto;
ENTRY
    npx esbuild _pki-entry.mjs --bundle --format=cjs --platform=node --minify \
      --external:node:crypto --external:crypto \
      --outfile=lib/vendor/pki.cjs
    rm _pki-entry.mjs
    sed -i "1s|^|// Peculiar PKI — vendored @peculiar/x509 v${X509_VER} + pkijs v${PKIJS_VER}\n// License: MIT. Bundled with esbuild.\n// Exports: { pkijs, x509, crypto (node:webcrypto bound) }\n// Includes: reflect-metadata, pvutils, pvtsutils, asn1js, @peculiar/asn1-*\n// Used by lib/mtls-engine-default.js for pure-JS CA + PKCS#12 operations.\n|" lib/vendor/pki.cjs
    INSTALLED_VER="${X509_VER}+pkijs-${PKIJS_VER}"
    ;;

  *)
    echo "Unknown package: $PKG"
    echo "Add a case to this script for bundling instructions."
    npm uninstall "$PKG" --no-save 2>/dev/null || true
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
  console.log('Updated MANIFEST.json: ' + pkg + ' -> ' + '$INSTALLED_VER');
} else {
  console.log('NOTE: ' + pkg + ' not in MANIFEST.json — add the entry manually');
}
"

# Clean up node_modules
if [ "$PKG" = "peculiar-pki" ]; then
  npm uninstall reflect-metadata pvutils pvtsutils asn1js \
    "@peculiar/asn1-schema" "@peculiar/asn1-x509" "@peculiar/asn1-ecc" "@peculiar/asn1-rsa" \
    "@peculiar/x509" pkijs --no-save 2>/dev/null || true
else
  npm uninstall "$PKG" --no-save 2>/dev/null || true
fi

# Verify the bundle has no unresolved requires after the npm cleanup
echo ""
echo "=== Verifying bundle integrity ==="
node -e "
var m = require('./$MANIFEST');
var p = m.packages['$PKG'];
if (!p || !p.files) { console.log('  (no files entry; skipping)'); process.exit(0); }
var ok = true;
Object.values(p.files).forEach(function(f) {
  if (typeof f !== 'string' || !f.endsWith('.cjs')) return;
  try { require('./' + f); console.log('  ' + f + ': OK'); }
  catch(e) { console.log('  ' + f + ': FAIL — ' + e.message); ok = false; }
});
if (!ok) process.exit(1);
" || { echo "Bundle verification failed — do not commit."; exit 1; }

echo ""
echo "=== Bundle sizes ==="
node -e "
var fs = require('fs');
var m = JSON.parse(fs.readFileSync('$MANIFEST', 'utf8'));
var p = m.packages['$PKG'];
if (!p) process.exit();
Object.values(p.files || {}).forEach(function(f) {
  if (typeof f !== 'string') return;
  try {
    var s = fs.statSync(f);
    console.log('  ' + f + ': ' + (s.size / 1024).toFixed(1) + ' KB');
  } catch(_e) {}
});
"

echo ""
echo "=== Refreshing MANIFEST.json sha256 hashes ==="
# Hashes track the on-disk vendored bundle. Without this final refresh
# the bundledAt and version fields in MANIFEST.json drift ahead of
# hashes.server, and the vendor-manifest smoke gate fails on the next
# test run. Auto-running the refresh keeps the supply-chain integrity
# story mechanically authoritative rather than relying on operator
# memory to run the second step.
node scripts/refresh-vendor-manifest.js || { echo "Manifest hash refresh failed."; exit 1; }

echo ""
echo "=== Done: $PKG v$INSTALLED_VER vendored ==="
echo ""
echo "Next steps:"
echo "  1. node test/smoke.js"
echo "  2. cd examples/wiki && rm -rf data data-e2e && node test/e2e.js"
echo "  3. git add lib/vendor/ && git commit"
