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

FROM gcr.io/oss-fuzz-base/base-builder-javascript

# Copy the framework source. ClusterFuzzLite mounts the repo at
# $SRC/blamejs, so we COPY everything (including fuzz/) into one
# place under $SRC.
COPY . $SRC/blamejs

# Build script wires `compile_javascript_fuzzer` for each harness.
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/blamejs
