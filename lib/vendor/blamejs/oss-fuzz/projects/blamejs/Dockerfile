# OSS-Fuzz project Dockerfile for blamejs.
#
# To submit upstream: copy this entire `oss-fuzz/projects/blamejs/`
# directory to `projects/blamejs/` in https://github.com/google/oss-fuzz
# and open a PR there. See `oss-fuzz/projects/blamejs/README.md` in
# this repo for the full submission procedure.

# The base-builder is digest-pinned here (mirroring the .clusterfuzzlite/ copy
# that Dependabot tracks — scripts/pin-all.js keeps the two in sync) so OpenSSF
# Scorecard sees a pinned base: this in-repo template is only ever SCANNED,
# never built by OSS-Fuzz's own infra. The actual upstream OSS-Fuzz submission
# un-pins the FROM in its own PR per OSS-Fuzz convention (that infra tracks the
# latest base-builder). This is a CI-only fuzzing image, never deployed.
FROM gcr.io/oss-fuzz-base/base-builder-javascript@sha256:990a7eb71a3001c3df3ae3b528e3797442d8666592ee24f86d4ce13b231db968

# Clone the framework into the build context. OSS-Fuzz builds against
# main on every run; once the project is accepted, ClusterFuzz tracks
# the latest commit. To pin a specific revision for reproducible
# builds, change the `-b main` reference to a tag.
RUN git clone --depth 1 -b main https://github.com/blamejs/blamejs $SRC/blamejs

WORKDIR $SRC/blamejs

# Build script wires `compile_javascript_fuzzer` for each harness.
COPY build.sh $SRC/
