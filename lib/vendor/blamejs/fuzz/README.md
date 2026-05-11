# Fuzz harnesses

Coverage-guided fuzz targets against the parser / validator surface
most likely to crash on adversarial input. Each `<name>.fuzz.js` file
is a libFuzzer-compatible harness (jazzer.js format) consumed by:

- **ClusterFuzzLite** locally on every PR + nightly batch — see
  `.clusterfuzzlite/` and `.github/workflows/cflite_*.yml`.
- **OSS-Fuzz** upstream once the submission lands — see
  `oss-fuzz/projects/blamejs/`.

Both pipelines feed the same harnesses with the same seed corpora;
findings reproduce identically.

## Targets

| File                              | Target                              |
| --------------------------------- | ----------------------------------- |
| `safe-json.fuzz.js`               | `b.safeJson.parse`                  |
| `safe-url.fuzz.js`                | `b.safeUrl.parse`                   |
| `safe-jsonpath.fuzz.js`           | `b.safeJsonPath.validateExpression` |
| `guard-csv.fuzz.js`               | `b.guardCsv.validate`               |
| `guard-html.fuzz.js`              | `b.guardHtml.validate`              |
| `guard-json.fuzz.js`              | `b.guardJson.parse`                 |
| `guard-yaml.fuzz.js`              | `b.guardYaml.parse`                 |
| `guard-xml.fuzz.js`               | `b.guardXml.validate`               |
| `guard-svg.fuzz.js`               | `b.guardSvg.validate`               |
| `guard-markdown.fuzz.js`          | `b.guardMarkdown.validate`          |
| `guard-email.fuzz.js`             | `b.guardEmail.validateMessage`      |
| `parsers__safe-toml.fuzz.js`      | `b.parsers.toml.parse`              |
| `parsers__safe-yaml.fuzz.js`      | `b.parsers.yaml.parse`              |
| `parsers__safe-xml.fuzz.js`       | `b.parsers.xml.parse`               |
| `parsers__safe-ini.fuzz.js`       | `b.parsers.ini.parse`               |

Each harness exports a `fuzz(data)` function the engine drives with
mutated bytes. The shared `_expected.js` helper classifies caught
errors: operator-friendly framework codes (`<domain>/<error>` or
`<domain>.<error>` shape) + node-builtin error subclasses with
input-shape messaging are EXPECTED outcomes — the harness returns
normally. Anything else escapes as a finding; libFuzzer records the
reproducer and persists it in the corpus.

Per-target seed corpora live in `fuzz/<name>_seed_corpus/`. Each file
is a single seed input; the build script zips them at compile time.
Add new seeds whenever a real-world input class isn't covered (raw
attack payloads, regression inputs from past bug fixes, etc.).

## Run locally

The simplest path is to let ClusterFuzzLite drive it via Docker:

```sh
# Build the image once:
docker build -t blamejs-cflite -f .clusterfuzzlite/Dockerfile .

# Run one harness for 60s:
docker run --rm -e FUZZING_LANGUAGE=javascript -e SANITIZER=address \
  -v $PWD/out:/out blamejs-cflite \
  bash -c 'bash $SRC/build.sh && /out/safe-json -max_total_time=60'
```

Pure-Node mode (no Docker, no coverage guidance — useful for a
sanity check on a harness edit):

```sh
npx --yes @jazzer.js/core fuzz/safe-json.fuzz.js -- -max_total_time=60
```

## CI

| Workflow                       | Trigger                       | Per-target budget |
| ------------------------------ | ----------------------------- | ----------------- |
| `cflite_pr.yml`                | PRs touching `lib/` / `fuzz/` | 300s              |
| `cflite_batch.yml` (batch)     | daily 05:17 UTC               | 1800s             |
| `cflite_batch.yml` (coverage)  | daily 05:17 UTC               | 600s              |

Findings show up as PR annotations + SARIF in the Security tab.
Corpora persist across runs via GH Actions artifacts so an input
that broke a previous PR remains in the seed set for future ones.

## Coverage gate

The fuzz-coverage detector in
`test/layer-0-primitives/codebase-patterns.test.js` enforces that
every `lib/safe-*.js` and `lib/guard-*.js` file (recursively) has a
corresponding `fuzz/<name>.fuzz.js` OR an explicit
`FUZZ_NOT_REQUIRED` allowlist entry with reason. A future parser
primitive can't ship without fuzz coverage.

## Adding a new target

1. Identify the primitive (`b.<thing>.<method>`) — must take
   operator-supplied bytes / strings as adversarial input.
2. Create `fuzz/<base>.fuzz.js` (or `<dir>__<base>.fuzz.js` for
   nested-path lib files):

   ```js
   "use strict";
   var b        = require("..");
   var expected = require("./_expected");

   module.exports.fuzz = function (data) {
     var input;
     try { input = data.toString("utf8"); }
     catch (_e) { return; }
     try {
       b.<thing>.<method>(input);
     } catch (e) {
       if (expected.isExpected(e)) return;
       throw e;
     }
   };
   ```

3. Create the seed-corpus directory `fuzz/<base>_seed_corpus/` and
   drop 3-10 realistic seed inputs (one per file).
4. Run codebase-patterns smoke gate to confirm coverage:
   `node test/layer-0-primitives/codebase-patterns.test.js`.
5. Verify the harness loads in jazzer.js:
   `npx @jazzer.js/core fuzz/<base>.fuzz.js -- -max_total_time=30`.

## What counts as a finding

The harness returns normally for documented refusals — the parser /
validator correctly rejected adversarial bytes. A finding is:

- Native `TypeError` with a non-input-shape message (suggests an
  internal invariant breach reaching unprotected code).
- `RangeError` outside the documented depth / length cap contract
  (suggests stack-overflow rather than guarded refusal).
- Prototype-pollution surface reaching the framework (the guard's
  source-level pre-scan should have refused before any parser ran).
- Anything else without an operator-friendly `err.code`.

libFuzzer records the reproducer + minimizes it; the resulting
minimal crash input ships as a corpus entry so future builds catch
the same regression instantly.
