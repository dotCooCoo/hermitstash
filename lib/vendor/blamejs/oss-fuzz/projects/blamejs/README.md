# OSS-Fuzz integration for blamejs

Submission-ready project config for Google's [OSS-Fuzz](https://github.com/google/oss-fuzz)
continuous-fuzzing service. Mirrors the local ClusterFuzzLite setup
under `.clusterfuzzlite/` — same harness shape, same build script,
same seed corpus.

## How upstream submission works

OSS-Fuzz lives in a single Google-owned repository
(`github.com/google/oss-fuzz`) with one directory per integrated
project. To add blamejs:

1. **Fork [`google/oss-fuzz`](https://github.com/google/oss-fuzz)** on
   GitHub.

2. **Copy** every file in this directory (`oss-fuzz/projects/blamejs/`)
   to `projects/blamejs/` in the fork. The destination tree is:

   ```
   projects/
     blamejs/
       Dockerfile
       build.sh
       project.yaml
       README.md       (this file — optional but recommended)
   ```

3. **Verify the build locally** using the OSS-Fuzz toolchain:

   ```
   git clone https://github.com/google/oss-fuzz
   cd oss-fuzz
   cp -r ../path/to/blamejs/oss-fuzz/projects/blamejs projects/

   python infra/helper.py build_image blamejs
   python infra/helper.py build_fuzzers blamejs
   python infra/helper.py check_build blamejs
   python infra/helper.py run_fuzzer blamejs safe-json
   ```

   Each fuzz target must build and run cleanly. The `check_build`
   step verifies every harness loads, links against libFuzzer, and
   actually exercises the framework code.

4. **Open a PR** against `google/oss-fuzz`. The OSS-Fuzz maintainers
   ([acceptance criteria](https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/))
   review for:
   - The project is open-source, security-critical (or has a
     non-trivial user base).
   - At least one named maintainer (`primary_contact` in
     `project.yaml`) commits to triaging crash reports.
   - The fuzz targets exercise real code paths (not no-op harnesses).

   blamejs qualifies on all three (server-side framework with
   security-on-by-default posture; sole maintainer named in
   `project.yaml`; the harnesses exercise the same content-safety +
   parser-validator surface ClusterFuzzLite tests on every PR).

5. **Post-merge**, ClusterFuzz starts fuzzing continuously. Crash
   reports arrive at `primary_contact` with a 90-day disclosure
   window. The project page lands at
   `https://issues.oss-fuzz.com/issues?q=blamejs`.

## Why bother when ClusterFuzzLite already runs?

| | ClusterFuzzLite (local) | OSS-Fuzz (upstream) |
|---|---|---|
| Where | GitHub Actions, per-PR + nightly | Google Cloud, 24/7 |
| Compute | Free GH runners | Free, but ~100× more CPU-hours |
| Corpus persistence | Workflow artifacts | Permanent on Google's storage |
| Crash deduplication | None | Built-in stack-trace clustering |
| Regression testing | Manual via re-runs | Automatic against every commit |
| Coverage reporting | Available | Public dashboard at `oss-fuzz.com` |

ClusterFuzzLite is the dev-time + PR-time gate; OSS-Fuzz is the
production background fuzzer that catches the bugs ClusterFuzzLite's
budget can't reach. Most security-mature frameworks run both — it's
the same harnesses, just two execution environments.

## Sync discipline

`.clusterfuzzlite/build.sh` and `oss-fuzz/projects/blamejs/build.sh`
must stay byte-for-byte identical (modulo this comment block) so a
crash that fires upstream reproduces locally and vice versa. The
`fuzz/*.fuzz.js` harnesses + `fuzz/<name>_seed_corpus/` directories
are the single source of truth — both Dockerfiles `COPY` them
directly.
