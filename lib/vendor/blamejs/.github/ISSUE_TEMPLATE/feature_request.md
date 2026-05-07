---
name: Feature request
about: Propose a new framework primitive, CLI subcommand, or operator-facing capability
title: ''
labels: enhancement
assignees: ''
---

<!--
Per CONTRIBUTING.md → "Ship complete, not incremental": every framework
primitive lands with the full operator-facing scope, not "minimum viable
with key features deferred." File the issue first to discuss scope before
opening a PR; it saves a round of rework.
-->

## Problem

<!-- What operator pain are you solving? Concrete scenario preferred over abstract. -->

## Proposed primitive / surface

<!-- What does the operator's API look like? Show the call site as you imagine it. -->

```js
// Imagined usage
var foo = b.foo.create({
  ...
});
await foo.doThing(...);
```

If it's a CLI subcommand, the imagined invocation:

```bash
blamejs foo do-thing --flag value
```

## Initial-release scope

What's IN the first shipped version:
-

What's explicitly OUT (and why each "out" is a complete decision, not a deferred bullet):
-

## Configuration surface

<!-- Which opts keys does the new primitive's create() accept? -->

```
allowedKeys: [
  "name",
  "audit",
  ...
]
```

## Failure modes

<!-- Pick the input-validation policy consciously per call site:

  - Boot-time / config-time inputs:  THROW with a clear error code so
    operators see the typo at boot, not at first request.
  - Hot-path observability sinks (audit / metrics / events):  DROP
    SILENT — these must never crash the request that triggered them.
  - Request-shape readers (request helpers, defensive parsers):
    RETURN DEFAULTS for missing / non-string input — the network sends
    what it sends; rejecting at the read site moves errors out of band.
-->

- Bad opts at `create()` → throw with code
- Hot-path sink failure → drop silent
- Bad request-shape input → return default

## Crypto / audit / security implications

<!-- Does this primitive touch the vault / sealed columns / audit chain? -->

- [ ] No crypto state involved
- [ ] Reads sealed columns (uses `b.cryptoField` automatically)
- [ ] Writes new sealed-by-default schema (declares `sealedFields` in the collection definition)
- [ ] Emits audit events (which namespace? does it need `audit.registerNamespace`?)
- [ ] Adds a new envelope-versioned algorithm (which ID? back-compat with old data?)

## Operator-facing surface

<!-- Where does this show up for operators? -->

- [ ] Wiki seeded docs updated (which concern group?)
- [ ] DEPLOY.md env vars updated
- [ ] CLI subcommand
- [ ] Admin UI demo in the wiki
- [ ] None — internal-only primitive

## Alternatives considered

<!-- What did you rule out and why. Saves the reviewer asking. -->

## Additional context
