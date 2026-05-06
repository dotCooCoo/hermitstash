"use strict";
/**
 * Multi-format safe parsers — apply the same security defaults blamejs's
 * b.json provides to other common data interchange formats.
 *
 * Currently shipped:
 *   xml  — RFC-compliant subset; XXE / DOCTYPE / billion-laughs blocked
 *           by default; depth + element + attribute count limits;
 *           numeric-character-ref bounds checked
 *   toml — TOML 1.0 parsing with depth + size limits;
 *           prototype-pollution rejection on dotted-key path segments;
 *           strict same-key redefinition (silent overwrite would mask
 *           config errors operators DO want surfaced); offset
 *           date-times decoded as JS Date, local date-time/date/time
 *           preserved as ISO strings (no implicit offset assumption);
 *           integers > MAX_SAFE_INTEGER rejected so 64-bit values
 *           must be encoded as quoted strings
 *   env  — .env file loader with size cap, schema validation, change
 *           tracking via audit chain, and Levenshtein-based typo
 *           detection. Rejects $VAR / ${VAR} expansion (consumers
 *           reading process.env later wouldn't know whether the
 *           value was literal or expanded). Rejects keys outside
 *           POSIX shape `^[A-Z_][A-Z0-9_]*$` by default. Schema
 *           registration declares per-key sensitivity tiers
 *           (boot-only / runtime / breaking) — `breaking` keys
 *           refuse silent change unless `{ allow: [...] }` opt-in.
 *           Diff result includes `suspicious` field flagging keys
 *           that look like typos of registered keys.
 *
 *   yaml — YAML 1.2 safe subset (JSON-shaped YAML). Rejects anchors
 *           (billion-laughs), aliases (cycles), tags (`!!python/object`-
 *           style deserialization), directives, multi-document
 *           streams, complex keys, merge keys (`<<`), and tabs in
 *           indentation. YAML 1.2 core-schema type inference (NOT
 *           1.1, which had the "Norway problem" where `country: NO`
 *           parsed as `country: false`). Block + flow style;
 *           literal `|` and folded `>` block scalars with chomp
 *           indicators.
 *   env  — .env file loader with size cap + schema validation;
 *           refuses to expand $VAR references; refuses to silently
 *           overwrite existing process.env values unless explicitly
 *           opted in. Dev-tooling — production secrets should still
 *           come through the operator's secrets-management; this is
 *           the local-development convenience.
 *   ini  — INI / .gitconfig / systemd-unit / php.ini / tox.ini parser.
 *           Sections (incl. [parent.child] / [parent "child"] nesting),
 *           ; or # comments (inline + leading), single + double quoting
 *           with \n / \t / \\ / \" / \' escapes, boolean coercion
 *           (true/false/yes/no/on/off), decimal + hex integers + floats.
 *           Prototype-pollution defense (__proto__/constructor/prototype
 *           rejected); duplicate-key policy throws by default
 *           (onDuplicate: "first"|"last" opts in to silent
 *           shadowing); section + per-section key + value-bytes
 *           caps configurable via opts.
 *
 * Public API:
 *   parsers.xml.parse(input, opts?)              → object
 *   parsers.ini.parse(input, opts?)              → object
 *   parsers.toml.parse(input, opts?)             → object
 *   parsers.yaml.parse(input, opts?)             → object
 *   parsers.env.load(filepath, opts?)            → { values, diff }
 *
 * (CSV moved to top-level `b.csv` in v0.5.17 — same surface unified.)
 *
 * Error types: each parser exports its own *SafeError class with .code
 * matching the format (xml/..., toml/..., ini/..., yaml/..., env/...).
 */
var safeEnv  = require("./safe-env");
var safeIni  = require("./safe-ini");
var safeToml = require("./safe-toml");
var safeXml  = require("./safe-xml");
var safeYaml = require("./safe-yaml");

module.exports = {
  xml:  safeXml,
  toml: safeToml,
  yaml: safeYaml,
  env:  safeEnv,
  ini:  safeIni,
};
