# wiki snippets

Each file under this tree is a runnable example referenced by the
`section({ example: "<path>" })` helper in `examples/wiki/lib/section.js`.

The helper reads the file at seed time and embeds it in the page body
inside a `<pre><code class="language-javascript">` block. Snippets are
NOT compiled or transformed — what's on disk is what ships.

## Conventions

- One file per primitive example. Filename = `<page-slug>/<primitive>.example.js`.
- Snippets must run end-to-end inside the e2e harness's sandbox. The
  primitive-section validator runs every javascript example block as
  part of the wiki e2e test (`test/validate-primitive-sections.js`,
  post-boot pass).
- Snippets keep their `"use strict"` directive visible — instructive
  for readers seeing the file in the wiki body.
- No dynamic require()s; the validator's harness scope is fixed.
- Per-request values (`req`, `res`, `db` rows) come from the harness's
  stub set when the snippet is run — write them as if you're inside a
  route handler.

## When to use a snippet vs. inline `example`

- Inline `example: "code goes here"` is fine for ≤10-line snippets.
- Snippets pay for themselves around the 15-line mark or when the
  example needs to ship multiple times across pages.
- Guard primitives have a special rule — re-use the framework's
  `INTEGRATION_FIXTURES` export rather than duplicating fixtures here.

## Adding a new snippet

1. Create the file under `<page>/<primitive>.example.js`.
2. Reference it from the page seeder via
   `section({ ..., example: "<page>/<primitive>.example.js" })`.
3. Run `cd examples/wiki && node test/e2e.js` — the primitive-section
   validator picks the snippet up automatically.
