# OSS-Fuzz project Dockerfile for blamejs.
#
# To submit upstream: copy this entire `oss-fuzz/projects/blamejs/`
# directory to `projects/blamejs/` in https://github.com/google/oss-fuzz
# and open a PR there. See `oss-fuzz/projects/blamejs/README.md` in
# this repo for the full submission procedure.

FROM gcr.io/oss-fuzz-base/base-builder-javascript

# Clone the framework into the build context. OSS-Fuzz builds against
# main on every run; once the project is accepted, ClusterFuzz tracks
# the latest commit. To pin a specific revision for reproducible
# builds, change the `-b main` reference to a tag.
RUN git clone --depth 1 -b main https://github.com/blamejs/blamejs $SRC/blamejs

WORKDIR $SRC/blamejs

# Build script wires `compile_javascript_fuzzer` for each harness.
COPY build.sh $SRC/
