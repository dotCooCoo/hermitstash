# ClusterFuzzLite build image for blamejs.
#
# Inherits from oss-fuzz's JavaScript base-builder (jazzer.js +
# libFuzzer + the compile_javascript_fuzzer helper pre-installed).
# Copy the framework source + harnesses, then build.sh wires each
# fuzz target into a libFuzzer-shaped runnable.
#
# ClusterFuzzLite consumes this same Dockerfile for the PR + batch
# fuzz workflows (`.github/workflows/cflite_*.yml`). OSS-Fuzz upstream
# uses the project-specific Dockerfile under `oss-fuzz/projects/blamejs/`
# which mirrors this shape — keep them in sync.
#
# The base is digest-pinned for a reproducible CI fuzz toolchain (Dependabot
# bumps it via the docker ecosystem entry for /.clusterfuzzlite). Note: the
# oss-fuzz/projects/blamejs/ copy is intentionally left on the floating tag —
# OSS-Fuzz's own build infra expects projects to track the latest base-builder,
# so pinning there would diverge from upstream convention.
FROM gcr.io/oss-fuzz-base/base-builder-javascript@sha256:990a7eb71a3001c3df3ae3b528e3797442d8666592ee24f86d4ce13b231db968

# Copy the framework source. ClusterFuzzLite mounts the repo at
# $SRC/blamejs, so we COPY everything (including fuzz/) into one
# place under $SRC.
COPY . $SRC/blamejs

# Build script wires `compile_javascript_fuzzer` for each harness.
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/blamejs
