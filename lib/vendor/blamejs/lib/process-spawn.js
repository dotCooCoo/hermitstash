"use strict";
/**
 * b.processSpawn — child-process launcher that strips connection-string
 * secrets from the environment before exec. Operators reaching for
 * `child_process.spawn` directly inherit `process.env` by default —
 * which means a child (jq, postgres CLI, an unzipper) sees
 * `DATABASE_URL`, `PG*`, `REDIS_URL`, `S3_*`, `AWS_*`. OWASP-1 closes
 * that class: every spawn through this primitive uses a filtered env
 * by default; operators opt in to specific secret env vars when the
 * child genuinely needs them.
 *
 *   var child = b.processSpawn.spawn("jq", [".name"], {
 *     stdio:    "pipe",
 *     // env: { ... }            // optional override; defaults to filtered
 *     // allowEnv: ["AWS_REGION"] // explicit pass-through whitelist
 *   });
 *
 * Filter list (case-insensitive — matches Windows env var names):
 *   DATABASE_URL, PG*, POSTGRES*, MYSQL*, REDIS_URL, MONGO_URL,
 *   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
 *   S3_*, AZURE_*, GCP_*, GOOGLE_APPLICATION_CREDENTIALS,
 *   *_TOKEN, *_SECRET, *_PASSWORD, *_API_KEY, *_PRIVATE_KEY.
 *
 * Audit: `process.spawn` (success) — metadata carries command + arg
 * count + which env vars were filtered out (NOT their values). On
 * exec failure: `process.spawn.failed` with the error code.
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
