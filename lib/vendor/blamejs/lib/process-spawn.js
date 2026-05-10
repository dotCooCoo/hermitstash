"use strict";
/**
 * @module b.processSpawn
 * @nav    Production
 * @title  Process Spawn
 *
 * @intro
 *   Secret-safe `child_process.spawn` wrapper — argv allowlist via
 *   the operator's caller, no `shell:true` reliance, env scrubbing of
 *   connection strings and credential variables, and output redaction
 *   in the audit metadata (env-var NAMES are recorded, never values).
 *
 *   Operators reaching for `child_process.spawn` directly inherit
 *   `process.env` by default — which means a child (`jq`, the
 *   postgres CLI, an unzipper) sees `DATABASE_URL`, `PG*`, `REDIS_URL`,
 *   `S3_*`, `AWS_*`. OWASP-1 closes that class: every spawn through
 *   `b.processSpawn` uses a filtered env by default; operators opt in
 *   to specific secret env vars via `opts.allowEnv` when the child
 *   genuinely needs them.
 *
 *   Filter patterns (case-insensitive — matches Windows env-var
 *   capitalization too): `DATABASE_URL`, `PG*`, `POSTGRES*`, `MYSQL*`,
 *   `REDIS_URL`, `MONGO*`, `AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|
 *   SESSION_TOKEN)`, `S3_*`, `AZURE_*`, `GCP_*`,
 *   `GOOGLE_APPLICATION_CREDENTIALS`, suffixes `*_TOKEN`, `*_SECRET`,
 *   `*_PASSWORD`, `*_API_KEY`, `*_PRIVATE_KEY`, `*_PASSPHRASE`. The
 *   frozen pattern list is exposed as
 *   `b.processSpawn.FILTER_PATTERNS` for operator inspection.
 *
 *   Audit: `process.spawn` (success) — metadata carries command, arg
 *   count, and the redacted list of env-var names that were stripped.
 *
 * @card
 *   Secret-safe `child_process.spawn` wrapper — argv allowlist via the operator's caller, no `shell:true` reliance, env scrubbing of connection strings and credential variables, and output redaction in the audit metadata (env-var NAMES are recorded, never values).
 */

var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var ProcessSpawnError = defineClass("ProcessSpawnError", { alwaysPermanent: true });

// Patterns matched case-insensitively against env var NAMES (not values).
// Values are never logged or audited.
var FILTER_PATTERNS = [
  /^DATABASE_URL$/i,
  /^PG/i,                                          // PG*: PGHOST, PGPASSWORD, PGUSER, ...
  /^POSTGRES/i,
  /^MYSQL/i,
  /^REDIS_URL$/i,
  /^MONGO/i,
  /^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)$/i,
  /^S3_/i,
  /^AZURE_/i,
  /^GCP_/i,
  /^GOOGLE_APPLICATION_CREDENTIALS$/i,
  /_TOKEN$/i,
  /_SECRET$/i,
  /_PASSWORD$/i,
  /_API_KEY$/i,
  /_PRIVATE_KEY$/i,
  /_PASSPHRASE$/i,
];

function _shouldFilter(name) {
  for (var i = 0; i < FILTER_PATTERNS.length; i += 1) {
    if (FILTER_PATTERNS[i].test(name)) return true;
  }
  return false;
}

/**
 * @primitive b.processSpawn.filteredEnv
 * @signature b.processSpawn.filteredEnv(source, allowEnv)
 * @since     0.8.42
 * @status    stable
 * @related   b.processSpawn.spawn
 *
 * Pure helper that returns `{ env, filtered }` — `env` is `source`
 * with every variable matching `FILTER_PATTERNS` removed, except for
 * names listed in `allowEnv` (explicit pass-through). `filtered` is
 * the array of stripped variable names; values are never returned or
 * logged.
 *
 * `source` defaults to `process.env` when omitted. Useful for
 * pre-flight inspection (which secrets would the spawn drop?) without
 * actually launching a child.
 *
 * @example
 *   var report = b.processSpawn.filteredEnv({
 *     PATH:                 "/usr/bin",
 *     AWS_ACCESS_KEY_ID:    "AKIA...",
 *     AWS_SECRET_ACCESS_KEY: "wJalr...",
 *     AWS_REGION:           "us-east-1",
 *     DATABASE_URL:         "postgres://...",
 *   }, ["AWS_REGION"]);
 *   report.env.PATH;       // → "/usr/bin"
 *   report.env.AWS_REGION; // → "us-east-1"
 *   report.env.DATABASE_URL;       // → undefined
 *   report.filtered.indexOf("AWS_ACCESS_KEY_ID") !== -1; // → true
 *   report.filtered.indexOf("DATABASE_URL")      !== -1; // → true
 */
function filteredEnv(source, allowEnv) {
  var src = source || process.env;
  var allowSet = {};
  if (Array.isArray(allowEnv)) {
    for (var ai = 0; ai < allowEnv.length; ai += 1) {
      if (typeof allowEnv[ai] === "string") allowSet[allowEnv[ai]] = true;
    }
  }
  var out = {};
  var filtered = [];
  for (var k in src) {
    if (!Object.prototype.hasOwnProperty.call(src, k)) continue;
    if (allowSet[k] === true) { out[k] = src[k]; continue; }
    if (_shouldFilter(k)) { filtered.push(k); continue; }
    out[k] = src[k];
  }
  return { env: out, filtered: filtered };
}

/**
 * @primitive b.processSpawn.spawn
 * @signature b.processSpawn.spawn(command, args, opts)
 * @since     0.8.42
 * @status    stable
 * @related   b.processSpawn.filteredEnv, b.daemon.start, b.audit.safeEmit
 *
 * Spawn a child process with the connection-string filter applied to
 * `process.env` before exec. Returns the underlying
 * `child_process.ChildProcess` so operators can attach the usual
 * `stdout` / `stderr` / `close` listeners. Emits one `process.spawn`
 * audit row carrying the command, arg count, and the names (never
 * values) of the env vars that were stripped.
 *
 * Throws `ProcessSpawnError("process-spawn/bad-command")` when
 * `command` is not a non-empty string. `opts.env`, when supplied, is
 * trusted verbatim — operators that pass an explicit env take full
 * responsibility for what reaches the child.
 *
 * @opts
 *   stdio:    string | Array,                  // forwarded to child_process.spawn
 *   cwd:      string,                          // forwarded to child_process.spawn
 *   detached: boolean,                         // forwarded to child_process.spawn
 *   env:      object,                          // explicit override; bypasses filter
 *   allowEnv: string[],                        // pass-through whitelist applied to process.env
 *   ...                                        // every other Node spawn opt is forwarded
 *
 * @example
 *   var child = b.processSpawn.spawn(process.execPath, ["-e", "process.exit(0)"], {
 *     stdio:    "ignore",
 *     allowEnv: ["AWS_REGION"],
 *   });
 *   typeof child.pid; // → "number"
 *   child.kill();
 */
function spawn(command, args, opts) {
  if (typeof command !== "string" || command.length === 0) {
    throw new ProcessSpawnError("process-spawn/bad-command",
      "spawn: command must be a non-empty string");
  }
  opts = opts || {};
  // If operator passes opts.env explicitly, trust it verbatim — we
  // already gave them the override. Otherwise build a filtered env.
  var spawnOpts = Object.assign({}, opts);
  var filtered = [];
  if (spawnOpts.env === undefined) {
    var built = filteredEnv(process.env, opts.allowEnv);
    spawnOpts.env = built.env;
    filtered = built.filtered;
  }
  delete spawnOpts.allowEnv;
  var nodeChild = require("node:child_process");
  var child = nodeChild.spawn(command, args || [], spawnOpts);
  try {
    audit().safeEmit({
      action:  "process.spawn",
      outcome: "success",
      metadata: {
        command:        command,
        argCount:       Array.isArray(args) ? args.length : 0,
        filteredCount:  filtered.length,
        filteredNames:  filtered.slice(),
      },
    });
  } catch (_e) { /* audit best-effort */ }
  return child;
}

module.exports = {
  spawn:               spawn,
  filteredEnv:         filteredEnv,
  FILTER_PATTERNS:     Object.freeze(FILTER_PATTERNS.slice()),
  ProcessSpawnError:   ProcessSpawnError,
};
