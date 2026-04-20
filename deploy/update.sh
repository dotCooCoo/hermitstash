#!/usr/bin/env bash
# HermitStash — unattended updater for native installs
#
# Safe to run manually (idempotent) or on a schedule via
# hermitstash-update.timer (see deploy/hermitstash-update.timer).
#
# What it does:
#   1. Reads the installed version from package.json
#   2. Fetches the newest release that matches UPDATE_CHANNEL
#   3. If a newer version is available:
#        - captures a rollback point (current git SHA)
#        - applies the update via the selected UPDATE_STRATEGY
#        - restarts the hermitstash systemd service
#        - polls /health; on failure, rolls back and restarts again
#   4. Never crosses a major version boundary on its own — only patch/minor
#      within the current major (upgrading v1.* → v2.* is operator-initiated).
#
# Environment variables (all optional):
#   UPDATE_STRATEGY   git | release-tarball | signed-tarball  (default: git)
#   UPDATE_CHANNEL    stable | off                             (default: stable)
#   INSTALL_DIR       install directory                        (default: /opt/hermitstash)
#   SERVICE_NAME      systemd unit name                        (default: hermitstash)
#   PORT              health check port                        (default: 3000)
#   HEALTH_TIMEOUT    seconds to wait for healthy after restart (default: 60)
#   TRUSTED_KEYS_DIR  dir containing ECDSA pubkeys in PEM form (default: /etc/hermitstash/trusted-keys.d)
#   DRY_RUN           1 = log what would happen, don't apply   (default: 0)
#   FORCE             1 = apply even if no newer version found (default: 0)
#
# Exit codes:
#   0   no-op (up to date) OR update applied and healthy
#   10  update attempted but health check failed (rolled back)
#   20  precondition failed (missing dir, not a git repo, etc.)
#   30  network / release-metadata fetch failed
#   40  strategy not implemented (signed-tarball today)
#   50  concurrent invocation (lock held)
#
# ─── Strategy map ────────────────────────────────────────────────────────
#
# UPDATE_STRATEGY=git             Works today. `git fetch --tags` +
#                                 `git checkout vX.Y.Z` against the install
#                                 directory. Relies on HTTPS + the commit
#                                 history in the public repo — no app-level
#                                 signature check.
#
# UPDATE_STRATEGY=release-tarball Future. Download a release tarball from
#                                 GitHub + its SHA3-512 digest, verify the
#                                 digest, extract atomically. Integrity only,
#                                 no authenticity.
#
# UPDATE_STRATEGY=signed-tarball  Future. Same as release-tarball, plus
#                                 verify a detached P-384 ECDSA signature
#                                 against a pubkey in TRUSTED_KEYS_DIR.
#                                 This is the heavyweight target — it
#                                 requires a server release-signing key,
#                                 a CI job that signs on tag push, and
#                                 release assets named:
#                                     hermitstash-X.Y.Z.tar.gz
#                                     hermitstash-X.Y.Z.tar.gz.sha3-512
#                                     hermitstash-X.Y.Z.tar.gz.sig
#                                 See fetch_release_asset_url() and
#                                 verify_signature() for the exact seams.
#
# The three strategies share this script's skeleton (decide → acquire →
# verify → apply → restart → health-check → rollback). Adding the tarball
# paths is a matter of filling in acquire_release_<strategy>() and
# verify_release_<strategy>().

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────────────────

UPDATE_STRATEGY="${UPDATE_STRATEGY:-git}"
UPDATE_CHANNEL="${UPDATE_CHANNEL:-stable}"
INSTALL_DIR="${INSTALL_DIR:-/opt/hermitstash}"
SERVICE_NAME="${SERVICE_NAME:-hermitstash}"
PORT="${PORT:-3000}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-60}"
TRUSTED_KEYS_DIR="${TRUSTED_KEYS_DIR:-/etc/hermitstash/trusted-keys.d}"
DRY_RUN="${DRY_RUN:-0}"
FORCE="${FORCE:-0}"

GITHUB_REPO="${GITHUB_REPO:-dotCooCoo/hermitstash}"
LOCK_FILE="${LOCK_FILE:-/var/lock/hermitstash-update.lock}"

# ─── Logging ─────────────────────────────────────────────────────────────
# When invoked via systemd, stdout/stderr land in the journal and the
# leading "[...]" prefix makes the log lines filterable. When invoked at
# a TTY, colors help.

if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; NC=''
fi

log()  { echo -e "${GREEN}[hermitstash-update]${NC} $*"; }
warn() { echo -e "${YELLOW}[hermitstash-update]${NC} $*"; }
err()  { echo -e "${RED}[hermitstash-update]${NC} $*" >&2; }

# ─── Concurrency guard ───────────────────────────────────────────────────
# Prevent two timers (or a timer + a manual invocation) from racing.
# flock is in util-linux — always present on systemd systems.

exec 9>"$LOCK_FILE" 2>/dev/null || {
  err "Could not open lock file $LOCK_FILE — run as root, or set LOCK_FILE to a writable path."
  exit 20
}
if ! flock -n 9; then
  warn "Another update is already running — skipping this tick."
  exit 50
fi

# ─── Channel gate ────────────────────────────────────────────────────────

if [ "$UPDATE_CHANNEL" = "off" ]; then
  log "UPDATE_CHANNEL=off — auto-update disabled; exiting."
  exit 0
fi

# ─── Preconditions ───────────────────────────────────────────────────────

if [ ! -d "$INSTALL_DIR" ]; then
  err "Install directory not found: $INSTALL_DIR"
  exit 20
fi

if [ ! -f "$INSTALL_DIR/package.json" ]; then
  err "Not a HermitStash install directory (no package.json): $INSTALL_DIR"
  exit 20
fi

# ─── Version helpers ─────────────────────────────────────────────────────

# Read "version" from package.json without pulling in jq — our package.json
# is tiny and the field is stable at column 3.
read_current_version() {
  grep -Eo '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$INSTALL_DIR/package.json" \
    | head -1 \
    | sed -E 's/.*"([^"]+)"$/\1/'
}

# semver compare: returns 0 if $1 > $2, 1 otherwise. Treats A.B.C form only.
# Suffixes like -rc.1 are excluded from stable channel by tag filtering,
# so we don't need to handle them here.
version_gt() {
  # shellcheck disable=SC2206 # intentional word-split into array
  local A=(${1//./ }) B=(${2//./ })
  for i in 0 1 2; do
    local a="${A[$i]:-0}" b="${B[$i]:-0}"
    if [ "$a" -gt "$b" ] 2>/dev/null; then return 0; fi
    if [ "$a" -lt "$b" ] 2>/dev/null; then return 1; fi
  done
  return 1
}

major_of() { echo "${1%%.*}"; }

# ─── Release discovery ───────────────────────────────────────────────────
#
# Hit the GitHub API unauthenticated. Rate limit (60/hr) is plenty for a
# daily timer. No jq dependency — we grep for the tag_name field. The API
# returns JSON that's stable enough to parse this way, but if a future
# change breaks it, switch to `curl ... | python3 -c 'import json,sys;...'`
# since python3 is present on every distro we target.

fetch_latest_stable_tag() {
  local current_major="$1"
  local api="https://api.github.com/repos/${GITHUB_REPO}/releases"

  # The list endpoint returns up to 30 releases in newest-first order. We
  # iterate and return the first tag whose major matches and whose name
  # is a bare vX.Y.Z (no -rc, -beta, etc.).
  curl -fsSL -H 'Accept: application/vnd.github+json' "$api" \
    | grep -Eo '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' \
    | sed -E 's/.*"v?([^"]+)"$/\1/' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
    | while read -r ver; do
        if [ "$(major_of "$ver")" = "$current_major" ]; then
          echo "$ver"
          break
        fi
      done
}

# ─── Strategy: git ───────────────────────────────────────────────────────

acquire_release_git() {
  local target_version="$1"
  log "git fetch --tags origin"
  git -C "$INSTALL_DIR" fetch --tags --quiet origin
  log "git checkout v${target_version}"
  git -C "$INSTALL_DIR" -c advice.detachedHead=false checkout --quiet "v${target_version}"
}

# No-op — git's own commit integrity is the only check for this strategy.
verify_release_git() { return 0; }

rollback_git() {
  local prev_ref="$1"
  warn "Rolling back to ${prev_ref}"
  git -C "$INSTALL_DIR" -c advice.detachedHead=false checkout --quiet "$prev_ref"
}

# ─── Strategy: release-tarball (stub) ────────────────────────────────────
# Fills in once the release workflow publishes source tarballs + digests.
# Until then, selecting this strategy exits with code 40.

acquire_release_tarball() {
  err "UPDATE_STRATEGY=release-tarball is not yet implemented."
  err "Release assets hermitstash-X.Y.Z.tar.gz + .sha3-512 need to exist first."
  exit 40
}
verify_release_tarball() { return 0; }

# ─── Strategy: signed-tarball (stub) ─────────────────────────────────────
# Target for the heavyweight path. Insertion points:
#   1. fetch_release_asset_url "$version" "hermitstash-${version}.tar.gz.sig"
#   2. openssl dgst -sha3-512 -verify "$pubkey" -signature "$sigfile" "$tarball"
#      where $pubkey is any *.pem under TRUSTED_KEYS_DIR that validates the
#      signature. Multiple keys = signed-release key rotation support.
# The signing key itself is generated and kept offline; only its public
# half ever ships inside TRUSTED_KEYS_DIR on deployed hosts. This script
# needs no knowledge of how the signing key is stored server-side.

acquire_release_signed_tarball() {
  err "UPDATE_STRATEGY=signed-tarball is not yet implemented."
  err "Requires: release-signing key + CI signing step + ${TRUSTED_KEYS_DIR} populated."
  exit 40
}
verify_release_signed_tarball() { return 0; }

# ─── Strategy dispatch ───────────────────────────────────────────────────

acquire_release() {
  case "$UPDATE_STRATEGY" in
    git)             acquire_release_git "$@" ;;
    release-tarball) acquire_release_tarball "$@" ;;
    signed-tarball)  acquire_release_signed_tarball "$@" ;;
    *) err "Unknown UPDATE_STRATEGY: $UPDATE_STRATEGY"; exit 20 ;;
  esac
}

verify_release() {
  case "$UPDATE_STRATEGY" in
    git)             verify_release_git "$@" ;;
    release-tarball) verify_release_tarball "$@" ;;
    signed-tarball)  verify_release_signed_tarball "$@" ;;
    *) err "Unknown UPDATE_STRATEGY: $UPDATE_STRATEGY"; exit 20 ;;
  esac
}

rollback() {
  case "$UPDATE_STRATEGY" in
    git)             rollback_git "$@" ;;
    # For tarball strategies, rollback will move aside .new and restore the
    # previous extract dir. Implemented when the forward path lands.
    *) warn "Rollback not implemented for strategy $UPDATE_STRATEGY"; return 1 ;;
  esac
}

# ─── Service control + health check ──────────────────────────────────────

restart_service() {
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY_RUN: would systemctl restart $SERVICE_NAME"
    return 0
  fi
  log "Restarting $SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
}

wait_for_healthy() {
  local deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -sf "http://localhost:${PORT}/health" > /dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# ─── Main flow ───────────────────────────────────────────────────────────

CURRENT="$(read_current_version)"
if [ -z "$CURRENT" ]; then
  err "Could not read current version from $INSTALL_DIR/package.json"
  exit 20
fi

CURRENT_MAJOR="$(major_of "$CURRENT")"
log "Current version: ${CURRENT} (major ${CURRENT_MAJOR})"
log "Strategy: ${UPDATE_STRATEGY}  Channel: ${UPDATE_CHANNEL}"

LATEST="$(fetch_latest_stable_tag "$CURRENT_MAJOR" || true)"
if [ -z "$LATEST" ]; then
  err "Could not determine latest ${CURRENT_MAJOR}.x.x release from ${GITHUB_REPO}."
  exit 30
fi
log "Latest ${CURRENT_MAJOR}.x.x release: ${LATEST}"

if [ "$FORCE" != "1" ] && ! version_gt "$LATEST" "$CURRENT"; then
  log "Up to date — nothing to do."
  exit 0
fi

# ─── Precondition: git repo (only checked for git strategy) ──────────────
if [ "$UPDATE_STRATEGY" = "git" ] && [ ! -d "$INSTALL_DIR/.git" ]; then
  err "$INSTALL_DIR is not a git working tree — cannot use UPDATE_STRATEGY=git."
  err "Either set UPDATE_STRATEGY=release-tarball (once implemented) or re-install from git."
  exit 20
fi

# ─── Rollback point ──────────────────────────────────────────────────────
ROLLBACK_REF=""
if [ "$UPDATE_STRATEGY" = "git" ]; then
  ROLLBACK_REF="$(git -C "$INSTALL_DIR" rev-parse HEAD)"
  log "Rollback ref captured: ${ROLLBACK_REF:0:12}"
fi

# ─── Dry run ─────────────────────────────────────────────────────────────
if [ "$DRY_RUN" = "1" ]; then
  log "DRY_RUN: would update ${CURRENT} → ${LATEST} via ${UPDATE_STRATEGY}"
  exit 0
fi

# ─── Apply ───────────────────────────────────────────────────────────────
log "Updating ${CURRENT} → ${LATEST}"
acquire_release "$LATEST"
verify_release "$LATEST"

restart_service

if wait_for_healthy; then
  log "Update complete — ${LATEST} is healthy."
  exit 0
fi

# ─── Rollback ────────────────────────────────────────────────────────────
err "Health check failed ${HEALTH_TIMEOUT}s after restart — rolling back."
if [ -n "$ROLLBACK_REF" ]; then
  rollback "$ROLLBACK_REF" || err "Rollback command itself failed — service is in an unknown state."
  restart_service
  if wait_for_healthy; then
    warn "Rollback to ${ROLLBACK_REF:0:12} restored health. Investigate ${LATEST} before retrying."
    exit 10
  fi
  err "Service still unhealthy after rollback. Manual intervention required."
  exit 10
fi

err "No rollback ref captured — cannot recover automatically."
exit 10
