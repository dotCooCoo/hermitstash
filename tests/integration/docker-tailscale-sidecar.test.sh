#!/usr/bin/env bash
# Docker-level integration test for the opt-in Tailscale sidecar in
# docker-entrypoint.sh. Requires Docker + outbound network (the enabled case
# installs the Tailscale package from the Wolfi repo at boot). This is NOT part
# of the offline unit/E2E suite — run it explicitly:
#
#   IMAGE=ghcr.io/dotcoocoo/hermitstash:1.14.3 bash tests/integration/docker-tailscale-sidecar.test.sh
#
# With no IMAGE set, it builds the image from the repo Dockerfile.
#
# It asserts the two contract-critical behaviours:
#   1. TAILSCALE_ENABLED=true  → the sidecar is installed + tailscaled starts,
#      the tailnet bring-up degrades gracefully with no authkey, and the app
#      STILL boots (every sidecar step is non-fatal).
#   2. TAILSCALE_ENABLED unset  → nothing Tailscale is installed and the app
#      boots identically (the feature is truly opt-in).
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${IMAGE:-}"
FAILED=0
C1="hs-ts-enabled-$$"
C2="hs-ts-disabled-$$"

# Invoked via the EXIT trap below (shellcheck can't see trap string targets).
# shellcheck disable=SC2329
cleanup() { docker rm -f "$C1" "$C2" >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass() { echo "  ok   - $1"; }
fail() { echo "  FAIL - $1"; FAILED=1; }

# check <description> <command...>     — pass when the command succeeds
check()     { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
# check_not <description> <command...> — pass when the command FAILS
check_not() { local d="$1"; shift; if "$@"; then fail "$d"; else pass "$d"; fi; }

# has_line / installed are dispatched by check/check_not as "$@" — shellcheck
# can't trace indirect invocation, so it reports them as unused (SC2329).
# shellcheck disable=SC2329
has_line()  { grep -qE "$2" <<<"$1"; }
# shellcheck disable=SC2329
installed() { docker exec "$1" sh -c 'command -v tailscaled >/dev/null 2>&1'; }

if [ -z "$IMAGE" ]; then
  IMAGE="hermitstash-ts-test:local"
  echo "== building image from $ROOT/Dockerfile =="
  docker build -t "$IMAGE" "$ROOT" || { echo "docker build failed"; exit 1; }
fi
echo "== image: $IMAGE =="

# Wait (<=120s) for a log line to appear in a container, else return 1.
wait_for_log() {
  local name="$1" pat="$2"
  for _ in $(seq 1 40); do
    if docker logs "$name" 2>&1 | grep -qE "$pat"; then return 0; fi
    sleep 3
  done
  return 1
}

# ---------------------------------------------------------------------------
echo "== scenario 1: TAILSCALE_ENABLED=true =="
docker rm -f "$C1" >/dev/null 2>&1 || true
docker run -d --name "$C1" \
  -e TAILSCALE_ENABLED=true \
  -e TAILSCALE_SERVE_MODE=serve \
  -e TAILSCALE_AUTHKEY= \
  -e PORT=3000 -e NODE_ENV=production \
  --shm-size=256m "$IMAGE" >/dev/null 2>&1 || { echo "run failed"; exit 1; }

wait_for_log "$C1" "HermitStash is running|install failed" || true
L1="$(docker logs "$C1" 2>&1)"

check     "attempts the signature-verified apk install" has_line "$L1" "\[tailscale\] installing sidecar via apk"
check     "tailscaled is installed at boot"              installed "$C1"
check     "starts tailscaled in userspace-networking"    has_line "$L1" "\[tailscale\] starting tailscaled \(userspace networking\)"
check     "skips tailscale up gracefully with no authkey" has_line "$L1" "TAILSCALE_AUTHKEY not set"
check     "the app still boots (sidecar is non-fatal)"   has_line "$L1" "HermitStash is running"

# ---------------------------------------------------------------------------
echo "== scenario 2: TAILSCALE_ENABLED unset (opt-in off) =="
docker rm -f "$C2" >/dev/null 2>&1 || true
docker run -d --name "$C2" \
  -e PORT=3000 -e NODE_ENV=production \
  --shm-size=256m "$IMAGE" >/dev/null 2>&1 || { echo "run failed"; exit 1; }

wait_for_log "$C2" "HermitStash is running" || true
L2="$(docker logs "$C2" 2>&1)"

check_not "no Tailscale activity when the feature is off" has_line "$L2" "\[tailscale\]"
check_not "tailscaled is NOT installed when off"          installed "$C2"
check     "the app boots normally with Tailscale off"    has_line "$L2" "HermitStash is running"

# ---------------------------------------------------------------------------
echo ""
if [ "$FAILED" -eq 0 ]; then echo "All Docker Tailscale-sidecar assertions passed."; else echo "Docker Tailscale-sidecar test FAILED."; fi
exit "$FAILED"
