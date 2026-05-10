# Wiki validation chain — audit findings

Audit of `source-doc-parser.js`, `validate-source-comment-blocks.js`,
`validate-site-coverage.js`, `validate-nav-coverage.js`,
`find-missing-pages.js`, and `section.js` after the multi-agent migration.

## Real correctness bugs (fix)

### A. `_extractExportKeys` greedy regex matches first `};` (validate-source-comment-blocks.js:138)

Current: `/module\.exports\s*=\s*\{([\s\S]*?)\}\s*;/`. Lazy match
finds the EARLIEST `};` — which may be inside a method body, not the
end of the exports object. Files with shape:

```js
module.exports = {
  foo: function () { /* ... */ },
};
```

happen to work because there's no `};` inside `foo`. But:

```js
module.exports = {
  build: function () {
    return function () {};   // ← first `};` is HERE, not the export close
  },
};
```

would yield empty exports keys. **Real false-negative class** that
silently disables the missing-block check on legitimate files.

**Fix**: bracket-counting parser instead of regex.

### B. Multi-method `@signature` lines under-document (validate-source-comment-blocks.js:218)

`@primitive b.X.a` + `@signature b.X.a(opts) / b.X.b(opts)`: only `a`
gets added to `documentedPrims`. `b` later triggers `missing-block`
because no `@primitive b.X.b` block exists.

**Fix**: parse `@signature` for all `b.X.Y` forms and register every
method name in `documentedPrims`.

### C. Factory-pattern arity mismatch forces misleading docs (validate-source-comment-blocks.js:166-175)

`_functionArity(source, name)` regex matches the FIRST `function NAME(...)`
in the source — for middleware files where `module.exports.create = function (opts) { return function X(req, res, next) {} }`, both
`function NAME(opts)` and inner `function X(req, res, next)` exist.
`pat3` matches the inner one (arity 3) when the export is the factory
(arity 1). Agents had to falsify `@signature b.middleware.X(req, res, next)` to satisfy the gate, hiding the operator-facing `(opts)` shape.

**Fix**: prefer the FIRST `function NAME(...)` declaration that
appears at top level (not nested inside a `return`).

### D. `module.exports.X = Y` form is invisible (validate-source-comment-blocks.js:138)

`_extractExportKeys` only matches `module.exports = { ... }` literal.
Files that build exports incrementally:

```js
module.exports.create = function () { ... };
module.exports.helper = helper;
```

return `null` from `_extractExportKeys` and the missing-block check
silently skips. **False negative** for any file using this shape.

**Fix**: also walk source for `module\.exports\.([a-zA-Z]\w*)\s*=` patterns.

## Coverage gaps in find-missing-pages.js

### E. Top-level function namespaces are skipped (find-missing-pages.js:138)

`if (entry.type !== 'object' || !entry.members) return;` skips
namespaces where `b.X` is itself a function (e.g. `b.createApp`).
Operators using `b.createApp(...)` find no wiki page.

**Fix**: also enumerate top-level function exports as 1-primitive
"namespaces."

### F. Constant-only namespaces are skipped

`primCount = filter(type === "function").length` — namespaces that
only export constants/objects (e.g. `b.constants.TIME`, `b.constants.BYTES`)
return primCount=0 and are skipped. Operators using `b.constants.TIME.minutes(5)` find no wiki coverage.

**Fix**: at minimum, surface them in a separate "constants" report
even if they don't take primitives.

### G. Filename heuristic is brittle (find-missing-pages.js:115)

Tries `<ns>.js`, kebab-case, `<ns>/index.js`. Misses:
- Cluster-namespaces split across multiple files (e.g.
  `b.middleware.csrfProtect` from `lib/middleware/csrf-protect.js`)
- Anything under custom subdirs

In practice the agents found these manually, but the discoverer
report mis-reports the lib file column.

**Fix**: probe deeper — when no match at top level, search recursively
for any file whose `@module` tag matches.

## Validator improvements (better signal, not bugs)

### H. Mixed-kind blocks aren't surfaced (source-doc-parser.js:194)

`if (tags.primitive) kind = "primitive"; else if (tags.module) ...`
silently picks one when both are present. Should be a finding.

### I. Posture catalog should be data-driven (validate-source-comment-blocks.js:70)

`KNOWN_POSTURES` is a hard-coded set in the validator. New regimes added
to `b.compliance` aren't recognized until the validator is updated.

**Fix**: read from `b.compliance.list()` at validate time.

### J. Forward-reference cross-refs are silently allowed

Soft-fail mode hides forward refs. A `--report-pending` mode would
list every soft-failed ref so operators see migration debt explicitly.

### K. `@example` parse-check is syntax-only

`_parseCheckExample` only verifies `vm.Script` parses. Example calling
`b.nonexistent.X()` parses fine. The legacy `validate-primitive-sections.js`
runs examples; the new validator doesn't.

**Fix**: add a runtime sandbox pass that imports the framework and
spot-checks symbol resolution on every `b.X.Y` reference in examples.

### L. `@section` heuristic is loose (source-doc-parser.js:184)

Sentence-shaped-prose detection in multi-line tag bodies fires on
any line matching `/^[A-Z]/` AND `/[.!?]$/`. Code lines like
`// Returns nothing.` would match. Low false-positive rate in
practice but not zero.

## Next-tier improvements (deferred)

- `_dedent` mixes tabs and spaces literally (`'\t' = 1 char` vs
  visual width). Edge case — unlikely in practice.
- The missing-block check skips `class XError {}` declarations
  (function-arity = -1). Error classes are documented elsewhere
  (error catalog harvester); this is intentional.

## Fix priority order

1. **A** — bracket-counting `_extractExportKeys`
2. **B** — multi-method `@signature` registration
3. **D** — `module.exports.X = Y` form
4. **C** — outer-vs-inner function arity
5. **E** — top-level function namespaces in find-missing-pages
6. **F** — constant-only namespace coverage report
7. **H** — surface mixed-kind blocks
