#!/usr/bin/env bash
# vendor-update.sh — update a vendored dependency in lib/vendor/
#
# Usage:
#   ./scripts/vendor-update.sh <package> [version]    # bundle (default: latest)
#   ./scripts/vendor-update.sh --check                # show outdated vendored packages
#   ./scripts/vendor-update.sh --diff <package>       # show vendored vs latest + changelog url
#   ./scripts/vendor-update.sh --diff-all             # diff every outdated package
#   ./scripts/vendor-update.sh --refresh-data [entry] # refresh + re-sign vendored data files
#                                                     # (publicsuffix-list, SecLists-common-
#                                                     # passwords-top-10000, bimi-trust-anchors;
#                                                     # default: all)
#
# What it does:
#   1. installs the package(s) temporarily via npm
#   2. bundles with esbuild (CJS, server-side, unminified — vendored
#      bundles ship as reviewable source so operators can diff them
#      against upstream; esbuild still tree-shakes and keeps upstream
#      license comments)
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
# and --diff-all to know which entries to walk. argon2 was removed in
# v0.4.x — Node 24's built-in `crypto.argon2*` replaced the prebuilds
# (see lib/argon2-builtin.js). The case-block below preserves the
# `argon2` operator-friendly error message for anyone who still tries
# `vendor-update.sh argon2`.
VENDORED_PACKAGES=("@noble/ciphers" "@noble/curves" "@noble/post-quantum" "@simplewebauthn/server" "@blamejs/pki")

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
    latest=$(npm view "$pkg" version 2>/dev/null || echo "?")
    if [ "$vendored" = "$latest" ]; then status="up to date"; else status="UPDATE AVAILABLE"; fi
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

# ---- refresh-data mode ----
#
# Vendored DATA files (not code bundles): fetch the upstream where one
# exists, re-append the in-payload integrity canary, and regenerate +
# re-sign the .data.js carrier via scripts/vendor-data-gen.js whenever
# the raw file changed. bimi-trust-anchors is operator-managed (no
# upstream to fetch) — it is re-signed only when the local .pem was
# edited per its file-header procedure. Runs of the CI vendor-currency
# gate that report the publicsuffix-list entry as stale are resolved by
# this mode. Requires the operator-local SLH-DSA signing key
# (.keys/vendor-data-private.pem; see scripts/vendor-data-keygen.js).

DATA_SIGNING_KEY=".keys/vendor-data-private.pem"
REFRESH_DATA_ANY_REGEN=false

fetch_upstream_raw() {
  # $1 url, $2 dest tmp path, $3.. fixed strings that must all appear
  # in the body (sanity gate — a truncated or error body must never
  # reach the signer).
  #
  # NOTE for this function and everything refresh_data_entry calls:
  # the entry functions run as `refresh_data_entry ... || exit 1`, and
  # bash suspends errexit inside a function invoked under || — every
  # state-changing command here must carry its own explicit failure
  # handling; none may rely on `set -e`.
  local url="$1" tmp="$2"
  shift 2
  if ! curl -fsSL --connect-timeout 30 --max-time 300 "$url" -o "$tmp"; then
    echo "ERROR: fetch failed: $url"
    rm -f "$tmp"
    return 1
  fi
  if [ ! -s "$tmp" ]; then
    echo "ERROR: fetched $url is empty — refusing to sign it"
    rm -f "$tmp"
    return 1
  fi
  local needle
  for needle in "$@"; do
    if ! grep -qF -- "$needle" "$tmp"; then
      echo "ERROR: fetched $url failed the sanity check (missing '$needle') — refusing to sign it"
      rm -f "$tmp"
      return 1
    fi
  done
  return 0
}

regen_data_module_if_changed() {
  # $1 manifest key, $2 raw file, $3 .data.js carrier, $4 generator
  # --name, $5 --source-url, $6 --license, $7 --canary ("" = none),
  # $8 NOTICE component match string ("" = no dated NOTICE stamp)
  #
  # Regenerates when the raw payload no longer matches the carrier's
  # recorded SHA-256 OR when the carrier itself fails four-layer
  # verification (a payload-identical carrier with a corrupted
  # signature block, a stripped header, or a signature from a rotated
  # key must be re-signable through this documented path, not by
  # reverse-engineering a manual generator invocation).
  local key="$1" raw="$2" datajs="$3" name="$4" srcurl="$5" license="$6" canary="$7" noticekey="$8"
  local rawsha datasha carrier_ok
  rawsha=$(node -e "var c=require('node:crypto'),f=require('node:fs');console.log(c.createHash('sha256').update(f.readFileSync(process.argv[1])).digest('hex'))" "$raw" 2>/dev/null) || rawsha=""
  if [ -z "$rawsha" ]; then
    echo "ERROR: cannot hash $raw — file missing or unreadable"
    return 1
  fi
  # Empty datasha (carrier missing, or its provenance header stripped)
  # is a regeneration trigger, never a match.
  datasha=$(node -e "var f=require('node:fs');var m=f.readFileSync(process.argv[1],'utf8').match(/^\/\/ SHA-256:\s+([0-9a-f]{64})/m);console.log(m?m[1]:'')" "$datajs" 2>/dev/null) || datasha=""
  carrier_ok=$(BLAMEJS_VENDOR_DATA_DEFER_BOOT_VERIFY=1 \
    BLAMEJS_VENDOR_DATA_DEFER_BOOT_VERIFY_REASON="vendor-update:per-entry-refresh-probe" \
    node -e "try { require('./lib/vendor-data.js').get(process.argv[1]); console.log('ok'); } catch (e) { console.log('bad'); }" "$name" 2>/dev/null) || carrier_ok="bad"
  if [ -n "$datasha" ] && [ "$rawsha" = "$datasha" ] && [ "$carrier_ok" = "ok" ]; then
    echo "  $name: carrier verified and matches the raw file — nothing to re-sign"
    return 0
  fi
  if [ -n "$datasha" ] && [ "$rawsha" = "$datasha" ]; then
    echo "  $name: carrier fails verification — regenerating + re-signing"
  else
    echo "  $name: raw file changed — regenerating + re-signing the carrier"
  fi
  local gen_args=(--src "$raw" --dst "$datajs" --name "$name" --source-url "$srcurl" --license "$license" --signing-key "$DATA_SIGNING_KEY")
  if [ -n "$canary" ]; then gen_args+=(--canary "$canary"); fi
  node scripts/vendor-data-gen.js "${gen_args[@]}" || return 1
  node -e "
var fs = require('fs');
var m = JSON.parse(fs.readFileSync('$MANIFEST', 'utf8'));
var key = process.argv[1];
if (m.packages[key]) {
  m.packages[key].bundledAt = process.argv[2] + 'T00:00:00Z';
  fs.writeFileSync('$MANIFEST', JSON.stringify(m, null, 2) + '\n');
  console.log('  MANIFEST.json: ' + key + ' bundledAt -> ' + process.argv[2]);
}
" "$key" "$DATE" || { echo "ERROR: MANIFEST.json bundledAt update failed for $key"; return 1; }
  if [ -n "$noticekey" ]; then
    node -e "
var fs = require('fs');
var sep = Array(81).join('-');
var noticeKey = process.argv[1];
var date = process.argv[2];
var blocks = fs.readFileSync('NOTICE', 'utf8').split(sep);
var touched = false;
for (var i = 0; i < blocks.length; i++) {
  if (blocks[i].indexOf('Component:') === -1 || blocks[i].indexOf(noticeKey) === -1) continue;
  var next = blocks[i].replace(/\(bundled \d{4}-\d{2}-\d{2}\)/, '(bundled ' + date + ')');
  if (next !== blocks[i]) { blocks[i] = next; touched = true; }
}
if (touched) {
  fs.writeFileSync('NOTICE', blocks.join(sep));
  console.log('  NOTICE: ' + noticeKey + ' bundled date -> ' + date);
}
" "$noticekey" "$DATE" || { echo "ERROR: NOTICE date update failed for $noticekey"; return 1; }
  fi
  REFRESH_DATA_ANY_REGEN=true
  return 0
}

refresh_data_entry() {
  local key="$1" tmp
  case "$key" in
    publicsuffix-list)
      tmp="lib/vendor/public-suffix-list.dat.refresh-tmp"
      fetch_upstream_raw "https://publicsuffix.org/list/public_suffix_list.dat" "$tmp" \
        "===END PRIVATE DOMAINS===" "// VERSION:" "// COMMIT:" || return 1
      { printf '\n// ===BEGIN blamejs canary===\n'
        printf '// Honeytoken — vendor-data integrity defense (lib/vendor-data.js).\n'
        printf '_blamejs_canary_v0_9_8_.local\n'
        printf '// ===END blamejs canary===\n'; } >> "$tmp"
      # Directional freshness guard: the list is CDN-served and an edge
      # can return an OLDER cached copy than the snapshot already
      # vendored (publication reaches edges at different times). The
      # VERSION header is a sortable UTC timestamp — never replace the
      # local file with a fetch whose VERSION is older than the local
      # one; a genuinely newer local copy is what the CI currency gate
      # already treats as current.
      local fetchv localv
      fetchv=$(grep -m1 '^// VERSION:' "$tmp" | awk '{print $3}') || fetchv=""
      localv=$(grep -m1 '^// VERSION:' "lib/vendor/public-suffix-list.dat" 2>/dev/null | awk '{print $3}') || localv=""
      if [ -n "$fetchv" ] && [ -n "$localv" ] && [[ "$fetchv" < "$localv" ]]; then
        echo "  public-suffix-list: fetched copy ($fetchv) is older than the vendored one ($localv) — lagging CDN edge; keeping the local file"
        rm -f "$tmp"
      elif cmp -s "$tmp" "lib/vendor/public-suffix-list.dat"; then
        echo "  public-suffix-list: upstream unchanged"
        rm -f "$tmp"
      else
        mv "$tmp" "lib/vendor/public-suffix-list.dat" || { echo "ERROR: could not replace lib/vendor/public-suffix-list.dat"; return 1; }
        echo "  public-suffix-list: raw file refreshed from upstream"
      fi
      regen_data_module_if_changed "publicsuffix-list" \
        "lib/vendor/public-suffix-list.dat" \
        "lib/vendor/public-suffix-list.data.js" \
        "public-suffix-list" \
        "https://publicsuffix.org/list/public_suffix_list.dat" \
        "MPL-2.0 (Mozilla Public Suffix List)" \
        "_blamejs_canary_v0_9_8_.local" \
        "publicsuffix-list"
      ;;
    SecLists-common-passwords-top-10000)
      tmp="lib/vendor/common-passwords-top-10000.txt.refresh-tmp"
      fetch_upstream_raw "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" "$tmp" \
        "password" || return 1
      if [ "$(grep -c . "$tmp")" -lt 9000 ]; then
        echo "ERROR: fetched password list has fewer than 9000 lines — refusing to sign it"
        rm -f "$tmp"
        return 1
      fi
      printf '\n_blamejs_canary_password_2026_05_13_blamejs_internal_\n' >> "$tmp"
      if cmp -s "$tmp" "lib/vendor/common-passwords-top-10000.txt"; then
        echo "  common-passwords-top-10000: upstream unchanged"
        rm -f "$tmp"
      else
        mv "$tmp" "lib/vendor/common-passwords-top-10000.txt" || { echo "ERROR: could not replace lib/vendor/common-passwords-top-10000.txt"; return 1; }
        echo "  common-passwords-top-10000: raw file refreshed from upstream"
      fi
      regen_data_module_if_changed "SecLists-common-passwords-top-10000" \
        "lib/vendor/common-passwords-top-10000.txt" \
        "lib/vendor/common-passwords-top-10000.data.js" \
        "common-passwords-top-10000" \
        "https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt" \
        "CC-BY-3.0 (SecLists / Daniel Miessler)" \
        "_blamejs_canary_password_2026_05_13_blamejs_internal_" \
        "SecLists"
      ;;
    bimi-trust-anchors)
      # Operator-managed — never fetched. Re-signs only when the local
      # .pem was edited per the refresh procedure in its file header.
      regen_data_module_if_changed "bimi-trust-anchors" \
        "lib/vendor/bimi-trust-anchors.pem" \
        "lib/vendor/bimi-trust-anchors.data.js" \
        "bimi-trust-anchors" \
        "https://bimigroup.org/resources/vmc-trust-anchors.pem" \
        "Public domain (BIMI Group VMC trust anchors)" \
        "" \
        ""
      ;;
    *)
      echo "ERROR: unknown data entry: $key"
      echo "       valid: publicsuffix-list, SecLists-common-passwords-top-10000, bimi-trust-anchors"
      return 1
      ;;
  esac
}

if [ "${1:-}" = "--refresh-data" ]; then
  if [ ! -f "$DATA_SIGNING_KEY" ]; then
    echo "ERROR: $DATA_SIGNING_KEY not found — the vendored-data SLH-DSA signing"
    echo "       key is operator-local. Generate a keypair with"
    echo "       scripts/vendor-data-keygen.js (shipping a new PUBLIC key is a"
    echo "       lib/vendor-data.js change and a breaking data-integrity event)."
    exit 1
  fi
  # A Ctrl-C'd or failed fetch must not leave a partial download inside
  # the shipped lib/vendor/ tree (the printed next step is `git add
  # lib/vendor/`). Belt: this trap. Braces: *.refresh-tmp is gitignored.
  trap 'rm -f lib/vendor/*.refresh-tmp' EXIT
  echo "=== Refreshing vendored data files ==="
  if [ -n "${2:-}" ]; then
    refresh_data_entry "$2" || exit 1
  else
    refresh_data_entry "publicsuffix-list" || exit 1
    refresh_data_entry "SecLists-common-passwords-top-10000" || exit 1
    refresh_data_entry "bimi-trust-anchors" || exit 1
  fi
  if [ "$REFRESH_DATA_ANY_REGEN" = true ]; then
    echo ""
    echo "=== Refreshing MANIFEST.json sha256 hashes ==="
    node scripts/refresh-vendor-manifest.js || { echo "Manifest hash refresh failed."; exit 1; }
  fi
  echo ""
  echo "=== Verifying vendored data (dual-hash + SLH-DSA + canary) ==="
  node -e "require('./lib/vendor-data.js').verifyAll(); console.log('  vendor-data verifyAll: OK');" || exit 1
  if [ "$REFRESH_DATA_ANY_REGEN" = true ]; then
    echo ""
    echo "Next steps:"
    echo "  1. node scripts/check-vendor-currency.js"
    echo "  2. node test/smoke.js"
    echo "  3. git add lib/vendor/ lib/vendor/MANIFEST.json NOTICE && git commit"
  else
    echo ""
    echo "Nothing changed — every vendored data file already matches upstream."
  fi
  exit 0
fi

# ---- update mode ----
PKG="${1:?Usage: vendor-update.sh <package> [version]}"
VER="${2:-latest}"

echo "=== Vendoring $PKG@$VER ==="

npm install "${PKG}@${VER}" --no-save --ignore-scripts 2>/dev/null
INSTALLED_VER=$(node -e "console.log(require('./node_modules/${PKG}/package.json').version)")
echo "Installed: $PKG@$INSTALLED_VER"

case "$PKG" in
  "@noble/ciphers")
    echo 'export { xchacha20poly1305 } from "@noble/ciphers/chacha.js";' > _entry.mjs
    npx esbuild _entry.mjs --bundle --format=cjs --platform=node --outfile=lib/vendor/noble-ciphers.cjs
    rm _entry.mjs
    BUNDLER_DESC="esbuild --format=cjs --platform=node"
    sed -i "1s|^|// XChaCha20-Poly1305 — vendored from @noble/ciphers v${INSTALLED_VER} by Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-ciphers\n// Bundled with esbuild. Exports: xchacha20poly1305\n|" lib/vendor/noble-ciphers.cjs
    ;;

  "@noble/curves")
    cat > _entry.mjs <<'ENTRY'
export { ristretto255_oprf } from "@noble/curves/ed25519.js";
export { p256_oprf, p384_oprf, p521_oprf } from "@noble/curves/nist.js";
ENTRY
    npx esbuild _entry.mjs --bundle --format=cjs --platform=node --outfile=lib/vendor/noble-curves.cjs
    rm _entry.mjs
    BUNDLER_DESC="esbuild --format=cjs --platform=node"
    sed -i "1s|^|// @noble/curves v${INSTALLED_VER} — vendored from Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-curves\n// Bundled with esbuild. Exports the RFC 9497 OPRF suites:\n//   ristretto255_oprf (ristretto255-SHA512), p256_oprf (P-256-SHA256),\n//   p384_oprf (P-384-SHA384), p521_oprf (P-521-SHA512) — each with\n//   oprf / voprf / poprf modes. Backs b.crypto.oprf.\n|" lib/vendor/noble-curves.cjs
    ;;

  "@noble/post-quantum")
    cat > _entry.mjs <<'ENTRY'
export { ml_kem512, ml_kem768, ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
export { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
export { slh_dsa_sha2_128f, slh_dsa_sha2_192f, slh_dsa_sha2_256f, slh_dsa_shake_128f, slh_dsa_shake_192f, slh_dsa_shake_256f } from "@noble/post-quantum/slh-dsa.js";
ENTRY
    npx esbuild _entry.mjs --bundle --format=cjs --platform=node --outfile=lib/vendor/noble-post-quantum.cjs
    rm _entry.mjs
    BUNDLER_DESC="esbuild --format=cjs --platform=node"
    sed -i "1s|^|// @noble/post-quantum v${INSTALLED_VER} — vendored from Paul Miller\n// License: MIT — https://github.com/paulmillr/noble-post-quantum\n// Bundled with esbuild. Exports: ml_kem512 / ml_kem768 / ml_kem1024 (FIPS 203 KEM),\n//   ml_dsa44 / ml_dsa65 / ml_dsa87 (FIPS 204 lattice signatures),\n//   slh_dsa_sha2_*f / slh_dsa_shake_*f (FIPS 205 hash signatures).\n|" lib/vendor/noble-post-quantum.cjs
    ;;

  "@simplewebauthn/server")
    # reflect-metadata (pulled in via @peculiar/x509) resolves to its upstream
    # ./lite entry: identical metadata API and cross-copy registry, but built
    # for runtimes with native globalThis / Map / Set / WeakMap — it has none
    # of the legacy global-object probes (Function("return this") / indirect
    # eval) that can never execute on the Node versions the framework supports.
    echo "module.exports = require(\"@simplewebauthn/server\");" > _entry.cjs
    npx esbuild _entry.cjs --bundle --format=cjs --platform=node --alias:reflect-metadata=reflect-metadata/lite --external:crypto --external:node:crypto --outfile=lib/vendor/simplewebauthn-server.cjs
    rm _entry.cjs
    BUNDLER_DESC="esbuild --format=cjs --platform=node --alias:reflect-metadata=reflect-metadata/lite --external:crypto --external:node:crypto"
    sed -i "1s|^|// @simplewebauthn/server v${INSTALLED_VER} — vendored. License: MIT\n// https://github.com/MasterKale/SimpleWebAuthn\n|" lib/vendor/simplewebauthn-server.cjs
    ;;

  "@blamejs/pki")
    # Zero-dep, pure-CJS PKI toolkit (X.509 / CRL / PKCS#12 / CMS, PQC-first).
    # Backs lib/mtls-engine-default.js. node:crypto stays external like the
    # other vendored bundles; nothing else is pulled in (no transitive deps).
    echo "module.exports = require(\"@blamejs/pki\");" > _entry.cjs
    npx esbuild _entry.cjs --bundle --format=cjs --platform=node --external:crypto --external:node:crypto --outfile=lib/vendor/blamejs-pki.cjs
    rm _entry.cjs
    BUNDLER_DESC="esbuild --format=cjs --platform=node --external:crypto --external:node:crypto"
    sed -i "1s|^|// @blamejs/pki v${INSTALLED_VER} — vendored (Apache-2.0). Zero-dep pure CJS.\n// https://github.com/blamejs/pki  Exports: x509, crl, pkcs12, key, webcrypto, schema, csr, cms, ...\n// Backs lib/mtls-engine-default.js (PQC-capable CA + PKCS#12 engine).\n|" lib/vendor/blamejs-pki.cjs
    ;;

  "argon2")
    echo "ERROR: argon2 is no longer vendored. The framework uses Node's built-in"
    echo "       crypto.argon2* (Node 24+) via lib/argon2-builtin.js. Operators"
    echo "       wanting to override pass an alternative argon2 impl through"
    echo "       opts to b.auth.password.{hash,verify,needsRehash}."
    exit 1
    ;;

  *)
    echo "Unknown package: $PKG"
    echo "Add a case to this script for bundling instructions."
    npm uninstall "$PKG" --no-save 2>/dev/null || true
    exit 1
    ;;
esac

# Update MANIFEST.json. COMPONENT_VERSIONS_JSON (set only for meta-bundles that
# carry a structured components[] sub-object, e.g. a future meta-bundle) is passed via
# the environment so its JSON braces/quotes don't fight the bash interpolation
# into the inline node script. BUNDLER_DESC records the esbuild invocation that
# actually produced the artifact, so the manifest's bundler field can never
# drift from the command in the case-block above.
COMPONENT_VERSIONS_JSON="${COMPONENT_VERSIONS_JSON:-}" BUNDLER_DESC="${BUNDLER_DESC:-}" node -e "
var fs = require('fs');
var m = JSON.parse(fs.readFileSync('$MANIFEST', 'utf8'));
var pkg = '$PKG';
if (m.packages[pkg]) {
  m.packages[pkg].version = '$INSTALLED_VER';
  m.packages[pkg].bundledAt = '$DATE';
  if (process.env.BUNDLER_DESC) { m.packages[pkg].bundler = process.env.BUNDLER_DESC; }
  // Derive structured SBOM component versions from the ACTUALLY-INSTALLED
  // packages (issue #366) so components[].version — the field CycloneDX / Trivy
  // / Grype key on — can never drift from the bundled version string.
  var compJson = process.env.COMPONENT_VERSIONS_JSON || '';
  if (compJson && m.packages[pkg].components) {
    var comps = JSON.parse(compJson);
    Object.keys(comps).forEach(function (c) {
      if (m.packages[pkg].components[c]) { m.packages[pkg].components[c].version = comps[c]; }
    });
  }
  // Keep the cpe version in sync with the install too — same SBOM-drift class
  // as components[] (#366): the cpe string encodes the version in field 5
  // (cpe:2.3:a:vendor:product:VERSION:...) and CVE scanners match against it.
  if (typeof m.packages[pkg].cpe === 'string') {
    var sv = (String('$INSTALLED_VER').match(/\d+\.\d+\.\d+/) || [null])[0];
    var parts = m.packages[pkg].cpe.split(':');
    if (sv && parts.length > 5) { parts[5] = sv; m.packages[pkg].cpe = parts.join(':'); }
  }
  fs.writeFileSync('$MANIFEST', JSON.stringify(m, null, 2) + '\n');
  console.log('Updated MANIFEST.json: ' + pkg + ' -> ' + '$INSTALLED_VER');
} else {
  console.log('NOTE: ' + pkg + ' not in MANIFEST.json — add the entry manually');
}
"

# Keep the NOTICE component version in sync with the install. NOTICE is an
# operator / compliance dependency inventory; a re-vendor that bumped the
# MANIFEST version but left NOTICE stale (as happened across five @blamejs/pki
# bumps) reports a false inventory. Match the block whose Component line names
# EXACTLY this package and rewrite its Version value (a replace FUNCTION, so no
# regex backreference has to survive the bash interpolation).
node -e "
var fs = require('fs');
var sep = Array(81).join('-');
var pkg = process.argv[1], ver = process.argv[2];
var blocks = fs.readFileSync('NOTICE', 'utf8').split(sep);
var touched = false;
for (var i = 0; i < blocks.length; i++) {
  if (blocks[i].indexOf('Component:') === -1) continue;
  var cm = blocks[i].match(/Component:\s+(\S+)/);
  if (!cm || cm[1] !== pkg) continue;
  var next = blocks[i].replace(/(Version:[ \t]+)\S+/, function (_, p) { return p + ver; });
  if (next !== blocks[i]) { blocks[i] = next; touched = true; }
}
if (touched) {
  fs.writeFileSync('NOTICE', blocks.join(sep));
  console.log('  NOTICE.txt: ' + pkg + ' version -> ' + ver);
}
" "$PKG" "$INSTALLED_VER" || { echo "ERROR: NOTICE version update failed for $PKG"; }

# Clean up node_modules
npm uninstall "$PKG" --no-save 2>/dev/null || true

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
