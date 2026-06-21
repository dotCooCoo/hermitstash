"use strict";
/**
 * cli — the engine behind `blamejs` on the command line.
 *
 * bin/blamejs.js is a 4-line shim that calls cli.main(process.argv.slice(2)).
 * Putting the dispatch logic in lib/ means tests drive it without
 * spawning a child process: pass argv + a captured-output writer +
 * env, get an exit code back.
 *
 *   var cli = b.cli;
 *   var captured = { out: "", err: "" };
 *   var rc = await cli.main(["migrate", "status", "--db", "./test.db"], {
 *     stdout: { write: function (s) { captured.out += s; } },
 *     stderr: { write: function (s) { captured.err += s; } },
 *     env:    {},
 *     cwd:    "/repo",
 *   });
 *
 * Subcommands ship one at a time as the framework grows. The
 * dispatch table is the registry — adding `vault rotate`, `audit verify`,
 * `subject export` etc. lands as new entries here, not new bin scripts.
 *
 * Currently shipped:
 *   blamejs migrate up    --db <path> [--dir <path>]
 *   blamejs migrate down  --db <path> [--dir <path>] [--steps N]
 *   blamejs migrate status --db <path> [--dir <path>]
 *   blamejs dev           --command <cmd> [--watch <dir>...] [--grace-ms N]
 *   blamejs version
 *   blamejs help [<command>]
 *
 * The migrate command operates against a node:sqlite file directly —
 * no vault / framework bootstrap. Encrypted-at-rest dbs are out of
 * scope for this slice; operators with that mode either run migrations
 * before encryption or temporarily switch the file to plaintext.
 */

var nodeFs = require("node:fs");
var os = require("node:os");
var nodePath = require("node:path");
var apiSnapshot = require("./api-snapshot");
var argParser = require("./arg-parser");
var atomicFile = require("./atomic-file");
var auditChain = require("./audit-chain");
var auditTools = require("./audit-tools");
var backup = require("./backup");
var canonicalJson = require("./canonical-json");
var cliHelpers = require("./cli-helpers");
var C = require("./constants");
var bCrypto = require("./crypto");
var dev = require("./dev");
var fileType = require("./file-type");
var guardRegex = require("./guard-regex");
var migrations = require("./migrations");
var passwordModule = require("./auth/password");
var requestHelpers = require("./request-helpers");
var restore = require("./restore");
var restoreBundle = require("./restore-bundle");
var restoreRollback = require("./restore-rollback");
var seeders = require("./seeders");
var vaultPassphraseOps = require("./vault/passphrase-ops");
var { defineClass } = require("./framework-error");

var CliError = defineClass("CliError", { alwaysPermanent: true });

// Maximum length for an operator-supplied --ignore regex pattern. Caps
// ReDoS surface area: a multi-megabyte pattern compiled to a regex
// would already be a footgun, so refuse anything beyond the cap.
var MAX_IGNORE_PATTERN_LENGTH = 0x100;

var DEFAULT_MIG_DIR = "./migrations";
var DEFAULT_SEED_DIR = "./seeders";

function _writeLine(stream, line) {
  if (!stream || typeof stream.write !== "function") return;
  stream.write(line + "\n");
}

// Minimal argv parser: positional args + flag map. Supports both
// `--flag value` and `--flag=value`. Single-dash forms (-v) treated
// as long aliases to keep the surface predictable. Routed through the
// reusable b.argParser.parseRaw primitive — every subcommand's hand-
// written flag validation continues to read the same { pos, flags }
// shape the cli has always exposed.
function _parseArgs(argv) {
  return argParser.parseRaw(argv);
}

function _resolvePath(p, cwd) {
  if (!p) return p;
  if (nodePath.isAbsolute(p)) return p;
  return nodePath.resolve(cwd || process.cwd(), p);
}

function _openSqlite(dbPath) {
  // Lazy-required so the CLI doesn't crash on `blamejs version` or
  // `blamejs help` if node:sqlite isn't usable for some reason.
  var { DatabaseSync } = require("node:sqlite");
  // Same SQLITE_LIMIT_ sqlLength cap as db.init's main handle — the CLI opens
  // the operator's real database for migrate / inspect, so the parse-time DoS
  // floor applies here too.
  return new DatabaseSync(dbPath, {
    limits: {
      sqlLength: C.BYTES.mib(1),
    },
  });
}

// ---- Subcommand: migrate ----

var MIGRATE_USAGE = [
  "Usage: blamejs migrate <subcommand> [flags]",
  "",
  "Subcommands:",
  "  up                Apply all pending migrations",
  "  down              Roll back the most-recent applied migration",
  "  status            Print applied + pending migrations",
  "",
  "Flags:",
  "  --db <path>       Path to the SQLite database file (required)",
  "  --dir <path>      Path to migrations directory (default ./migrations)",
  "  --steps <N>       For down: number of migrations to revert (default 1)",
].join("\n");

async function _runMigrate(args, ctx) {
  if (args.pos.length === 0) {
    _writeLine(ctx.stderr, MIGRATE_USAGE);
    return 2;
  }
  var sub = args.pos[0];
  if (sub === "help" || args.flags.help || args.flags.h) {
    _writeLine(ctx.stdout, MIGRATE_USAGE);
    return 0;
  }
  if (sub !== "up" && sub !== "down" && sub !== "status") {
    _writeLine(ctx.stderr, "blamejs migrate: unknown subcommand '" + sub + "'");
    _writeLine(ctx.stderr, MIGRATE_USAGE);
    return 2;
  }

  var dbPath = args.flags.db;
  if (!dbPath || dbPath === true) {
    _writeLine(ctx.stderr, "blamejs migrate " + sub + ": --db <path> is required");
    return 2;
  }
  dbPath = _resolvePath(String(dbPath), ctx.cwd);

  var dir = _resolvePath(String(args.flags.dir || DEFAULT_MIG_DIR), ctx.cwd);

  var db;
  try { db = _openSqlite(dbPath); }
  catch (e) {
    _writeLine(ctx.stderr, "blamejs migrate: cannot open db at " + dbPath +
      ": " + ((e && e.message) || String(e)));
    return 1;
  }

  try {
    var runner = migrations.create({ db: db, dir: dir });

    if (sub === "status") {
      var s = runner.status();
      _writeLine(ctx.stdout, "applied: " + s.applied.length + " / " + s.total);
      for (var i = 0; i < s.applied.length; i++) {
        _writeLine(ctx.stdout, "  ✓ " + s.applied[i].name +
          " (applied " + s.applied[i].appliedAt + ")");
      }
      _writeLine(ctx.stdout, "pending: " + s.pending.length);
      for (var j = 0; j < s.pending.length; j++) {
        _writeLine(ctx.stdout, "  · " + s.pending[j]);
      }
      return 0;
    }

    if (sub === "up") {
      var r = runner.up();
      if (r.applied.length === 0) {
        _writeLine(ctx.stdout, "no pending migrations (" + r.skipped.length + " already applied)");
      } else {
        _writeLine(ctx.stdout, "applied " + r.applied.length + " migration(s):");
        for (var k = 0; k < r.applied.length; k++) {
          _writeLine(ctx.stdout, "  ✓ " + r.applied[k]);
        }
      }
      return 0;
    }

    if (sub === "down") {
      var steps = args.flags.steps === undefined ? 1 : Number(args.flags.steps);
      if (!Number.isFinite(steps) || steps < 1 || Math.floor(steps) !== steps) {
        _writeLine(ctx.stderr, "blamejs migrate down: --steps must be a positive integer");
        return 2;
      }
      var rd = runner.down({ steps: steps });
      if (rd.reverted.length === 0) {
        _writeLine(ctx.stdout, "nothing to revert");
      } else {
        _writeLine(ctx.stdout, "reverted " + rd.reverted.length + " migration(s):");
        for (var m = 0; m < rd.reverted.length; m++) {
          _writeLine(ctx.stdout, "  ↶ " + rd.reverted[m]);
        }
      }
      return 0;
    }
  } catch (e) {
    var msg = (e && e.message) || String(e);
    var code = (e && e.code) || "ERROR";
    _writeLine(ctx.stderr, "blamejs migrate " + sub + ": " + code + ": " + msg);
    return 1;
  } finally {
    try { db.close(); } catch (_e) { /* close best-effort */ }
  }

  return 0;
}

// ---- Subcommand: seed ----

var SEED_USAGE = [
  "Usage: blamejs seed <subcommand> [flags]",
  "",
  "Subcommands:",
  "  run               Apply pending seeds for the given env",
  "  status            Print applied + pending seeds for the given env",
  "",
  "Flags:",
  "  --db <path>       Path to the SQLite database file               [required]",
  "  --env <name>      Environment to seed (dev / test / prod / ...)  [required]",
  "  --dir <path>      Path to seeders directory (default ./seeders)",
  "  --only <name>     Apply just one seed by filename (run subcommand only)",
  "  --force           Re-apply already-applied seeds (operator-explicit)",
].join("\n");

async function _runSeed(args, ctx) {
  if (args.pos.length === 0) {
    _writeLine(ctx.stderr, SEED_USAGE);
    return 2;
  }
  var sub = args.pos[0];
  if (sub === "help" || args.flags.help || args.flags.h) {
    _writeLine(ctx.stdout, SEED_USAGE);
    return 0;
  }
  if (sub !== "run" && sub !== "status") {
    _writeLine(ctx.stderr, "blamejs seed: unknown subcommand '" + sub + "'");
    _writeLine(ctx.stderr, SEED_USAGE);
    return 2;
  }

  var dbPath = args.flags.db;
  if (!dbPath || dbPath === true) {
    _writeLine(ctx.stderr, "blamejs seed " + sub + ": --db <path> is required");
    return 2;
  }
  dbPath = _resolvePath(String(dbPath), ctx.cwd);

  var env = args.flags.env;
  if (!env || env === true) {
    _writeLine(ctx.stderr, "blamejs seed " + sub + ": --env <name> is required");
    return 2;
  }

  var dir = _resolvePath(String(args.flags.dir || DEFAULT_SEED_DIR), ctx.cwd);

  var db;
  try { db = _openSqlite(dbPath); }
  catch (e) {
    _writeLine(ctx.stderr, "blamejs seed: cannot open db at " + dbPath +
      ": " + ((e && e.message) || String(e)));
    return 1;
  }

  try {
    var runner = seeders.create({ db: db, dir: dir });

    if (sub === "status") {
      var s = await runner.status({ env: String(env) });
      _writeLine(ctx.stdout, "env: " + s.env);
      _writeLine(ctx.stdout, "applied: " + s.applied.length + " / " + s.total);
      for (var i = 0; i < s.applied.length; i++) {
        _writeLine(ctx.stdout, "  ✓ " + s.applied[i].name +
          " (applied " + s.applied[i].appliedAt + ")");
      }
      _writeLine(ctx.stdout, "pending: " + s.pending.length);
      for (var j = 0; j < s.pending.length; j++) {
        _writeLine(ctx.stdout, "  · " + s.pending[j]);
      }
      if (s.rerunnable.length > 0) {
        _writeLine(ctx.stdout, "rerunnable: " + s.rerunnable.length);
        for (var k = 0; k < s.rerunnable.length; k++) {
          _writeLine(ctx.stdout, "  ↻ " + s.rerunnable[k]);
        }
      }
      return 0;
    }

    if (sub === "run") {
      var only = args.flags.only ? String(args.flags.only) : undefined;
      var force = !!args.flags.force;
      var r = await runner.run({ env: String(env), only: only, force: force });
      if (r.applied.length === 0) {
        _writeLine(ctx.stdout, "no seeds applied (" + r.skipped.length + " skipped)");
      } else {
        _writeLine(ctx.stdout, "applied " + r.applied.length + " seed(s):");
        for (var m = 0; m < r.applied.length; m++) {
          _writeLine(ctx.stdout, "  ✓ " + r.applied[m]);
        }
      }
      if (r.skipped.length > 0) {
        _writeLine(ctx.stdout, "skipped " + r.skipped.length + " (already applied)");
      }
      return 0;
    }
  } catch (e) {
    var msg = (e && e.message) || String(e);
    var code = (e && e.code) || "ERROR";
    _writeLine(ctx.stderr, "blamejs seed " + sub + ": " + code + ": " + msg);
    return 1;
  } finally {
    try { db.close(); } catch (_e) { /* close best-effort */ }
  }

  return 0;
}

// ---- Subcommand: dev ----

var DEV_USAGE = [
  "Usage: blamejs dev --command <cmd> [args] [flags]",
  "",
  "Spawn a child process and restart it on file changes.",
  "",
  "Flags:",
  "  --command <cmd>     Program to spawn (e.g. node)              [required]",
  "  --arg <value>       Argument for the spawned program (repeatable)",
  "  --watch <dir>       Directory to watch (repeatable; default '.')",
  "  --ignore <pattern>  Glob/regex fragment to ignore (repeatable)",
  "  --grace-ms <N>      Debounce window in ms (default 250)",
  "  --kill-signal <S>   Signal to send on restart (default SIGTERM)",
  "",
  "Example:",
  "  blamejs dev --command node --arg ./server.js --watch ./routes --watch ./views",
].join("\n");

function _coerceList(val) {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val.slice() : [val];
}

async function _runDev(args, ctx) {
  if (args.flags.help || args.flags.h) {
    _writeLine(ctx.stdout, DEV_USAGE);
    return 0;
  }
  var command = args.flags.command;
  if (!command || command === true) {
    _writeLine(ctx.stderr, "blamejs dev: --command <cmd> is required");
    _writeLine(ctx.stderr, DEV_USAGE);
    return 2;
  }
  var argList   = _coerceList(args.flags.arg).map(String);
  var watchList = _coerceList(args.flags.watch).map(String);
  var ignoreList = _coerceList(args.flags.ignore).map(function (s) {
    var str = String(s);
    if (str.length > MAX_IGNORE_PATTERN_LENGTH) {
      throw new CliError("cli/bad-ignore-pattern",
        "blamejs dev: --ignore pattern exceeds max length " +
        MAX_IGNORE_PATTERN_LENGTH + " (got " + str.length + ")");
    }
    // ReDoS / catastrophic-backtracking defense — refuses nested-quant
    // (CVE-2024-21538 class), consecutive-* (CVE-2026-26996), nested
    // extglob (CVE-2026-33671), and lookaround-quant shapes before the
    // pattern reaches RegExp(). Operator typo / hostile-input identical
    // shape from here on — both want the same refusal.
    try {
      guardRegex.sanitize(str, { profile: "strict" });
    } catch (e) {
      throw new CliError("cli/bad-ignore-pattern",
        "blamejs dev: --ignore pattern refused by guardRegex: " +
        ((e && e.message) || String(e)));
    }
    return RegExp(str);
  });
  var graceMs = args.flags["grace-ms"] !== undefined ? Number(args.flags["grace-ms"]) : undefined;
  if (graceMs !== undefined && (!Number.isFinite(graceMs) || graceMs < 0)) {
    _writeLine(ctx.stderr, "blamejs dev: --grace-ms must be a non-negative number");
    return 2;
  }
  var killSignal = args.flags["kill-signal"];

  var d = dev.create({
    command:    String(command),
    args:       argList,
    watch:      watchList.length ? watchList : undefined,
    ignore:     ignoreList.length ? ignoreList : undefined,
    graceMs:    graceMs,
    killSignal: typeof killSignal === "string" ? killSignal : undefined,
    cwd:        ctx.cwd,
    env:        ctx.env,
  });

  // Forward parent SIGINT/SIGTERM to the child via stop()
  var stopped = false;
  function shutdown() {
    if (stopped) return;
    stopped = true;
    d.stop().then(function () { /* exit naturally */ });
  }
  process.once("SIGINT",  shutdown);
  process.once("SIGTERM", shutdown);

  try {
    await d.start();
  } catch (e) {
    _writeLine(ctx.stderr, "blamejs dev: " + ((e && e.message) || String(e)));
    return 1;
  }
  // The dev loop runs until the operator interrupts. Resolve a
  // never-settling promise so main() awaits forever; the SIGINT handler
  // above flips stopped+resolves on Ctrl-C.
  await new Promise(function (resolve) {
    var iv = setInterval(function () {
      if (stopped) { clearInterval(iv); resolve(); }
    }, 250);
    if (typeof iv.unref === "function") iv.unref();
  });
  return 0;
}

// ---- Subcommand: api-snapshot ----

var API_SNAPSHOT_USAGE = [
  "Usage: blamejs api-snapshot <subcommand> [flags]",
  "",
  "Subcommands:",
  "  capture            Walk the framework's public surface and write a snapshot",
  "  compare            Diff the current surface against a saved snapshot",
  "",
  "Flags:",
  "  --file <path>      Snapshot file path (default ./api-snapshot.json)",
  "  --module <path>    Module to inspect (default require('@blamejs/core'))",
  "",
  "Exit codes:",
  "  0  no changes (compare) or write succeeded (capture)",
  "  1  breaking changes detected (compare)",
  "  2  bad invocation",
].join("\n");

function _resolveTargetModule(modulePath, ctx) {
  // Default: load index.js from the framework root (one level up from lib/cli.js).
  // Dynamic require by design — the CLI loads either the framework root index.js
  // or an operator-supplied module path from the command line. Operator-
  // extensibility surfaces by definition can't be statically traced by a
  // bundler — anyone bundling this CLI surface into SEA/pkg accepts that
  // runtime --module=<path> arguments won't resolve. Internal framework
  // code never reaches this nodePath.
  if (!modulePath) {
    var root = nodePath.resolve(__dirname, "..");
    return require(nodePath.join(root, "index.js"));   // allow:dynamic-require — operator-extensibility entry point
  }
  var abs = nodePath.isAbsolute(modulePath) ? modulePath : nodePath.resolve(ctx.cwd, modulePath);
  delete require.cache[require.resolve(abs)];
  return require(abs);                              // allow:dynamic-require — operator-extensibility entry point
}

function _runApiSnapshot(args, ctx) {
  if (args.flags.help || args.flags.h) {
    _writeLine(ctx.stdout, API_SNAPSHOT_USAGE);
    return 0;
  }
  if (args.pos.length === 0) {
    _writeLine(ctx.stderr, API_SNAPSHOT_USAGE);
    return 2;
  }
  var sub = args.pos[0];
  var file = String(args.flags.file || "./api-snapshot.json");
  var filePath = nodePath.isAbsolute(file) ? file : nodePath.resolve(ctx.cwd, file);
  var modulePathOpt = typeof args.flags.module === "string" ? args.flags.module : null;

  if (sub === "capture") {
    var target;
    try { target = _resolveTargetModule(modulePathOpt, ctx); }
    catch (e) {
      _writeLine(ctx.stderr, "blamejs api-snapshot capture: cannot load module: " +
        ((e && e.message) || String(e)));
      return 1;
    }
    var snap;
    try { snap = apiSnapshot.capture(target); }
    catch (e) {
      _writeLine(ctx.stderr, "blamejs api-snapshot capture: " +
        ((e && e.message) || String(e)));
      return 1;
    }
    apiSnapshot.write(snap, filePath);
    _writeLine(ctx.stdout, "wrote snapshot to " + filePath +
      " (frameworkVersion " + snap.frameworkVersion + ")");
    return 0;
  }

  if (sub === "compare") {
    var loaded;
    try { loaded = apiSnapshot.read(filePath); }
    catch (e) {
      _writeLine(ctx.stderr, "blamejs api-snapshot compare: " +
        ((e && e.message) || String(e)));
      return 1;
    }
    var current;
    try {
      var t = _resolveTargetModule(modulePathOpt, ctx);
      current = apiSnapshot.capture(t);
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs api-snapshot compare: cannot capture current surface: " +
        ((e && e.message) || String(e)));
      return 1;
    }
    var diff = apiSnapshot.compare(loaded, current);
    _writeLine(ctx.stdout, apiSnapshot.formatDiff(diff));
    if (diff.breaking.length > 0) return 1;
    return 0;
  }

  _writeLine(ctx.stderr, "blamejs api-snapshot: unknown subcommand '" + sub + "'");
  _writeLine(ctx.stderr, API_SNAPSHOT_USAGE);
  return 2;
}

// ---- Subcommand: audit ----
//
// Operator tooling on top of the audit chain. Programmatic API is at
// b.auditTools — the CLI is a thin wrapper that's easier to script
// against from operator runbooks (cron, retention pipelines, etc.).

var AUDIT_USAGE = [
  "Usage: blamejs audit <subcommand> [flags]",
  "",
  "Subcommands:",
  "  archive        Bundle audit rows older than --before into a verified archive",
  "  export         Auditor evidence bundle for a date range",
  "  verify-bundle  Round-trip integrity check on an archive or export bundle",
  "  verify-chain   Walk the live audit chain end-to-end; reports tampering",
  "  purge          Delete live rows already captured in a verified archive",
  "",
  "Common flags:",
  "  --out <path>           Output bundle directory (must NOT exist)",
  "  --in  <path>           Input bundle directory (verify-bundle, purge)",
  "  --passphrase <string>  Bundle passphrase (or env BLAMEJS_AUDIT_PASSPHRASE)",
  "",
  "archive flags:",
  "  --before <date>        Archive rows with recordedAt < this date (ISO-8601 or epoch ms)",
  "",
  "export flags:",
  "  --from <date>          Earliest recordedAt (inclusive)",
  "  --to <date>            Latest recordedAt (inclusive)",
  "  --action <name>        Restrict to a single audit action",
  "",
  "verify-chain flags:",
  "  --db <path>            SQLite database path (required)",
  "  --table <name>         Audit table name (default audit_log)",
  "  --max-rows <N>         Stop after walking N rows (default: walk all)",
  "",
  "purge flags:",
  "  --confirm              REQUIRED — operator acknowledgement of destructive op",
  "",
  "Exit codes:",
  "  0  success (or chain verified ok)",
  "  1  operation failed (or chain tampered)",
  "  2  bad invocation",
].join("\n");

function _resolvePassphrase(args, ctx) {
  if (typeof args.flags.passphrase === "string" && args.flags.passphrase.length > 0) {
    return args.flags.passphrase;
  }
  var env = ctx.env && ctx.env.BLAMEJS_AUDIT_PASSPHRASE;
  if (typeof env === "string" && env.length > 0) return env;
  return null;
}

function _resolveOutPath(p, ctx) {
  if (!p) return null;
  return nodePath.isAbsolute(p) ? p : nodePath.resolve(ctx.cwd, p);
}

async function _runAudit(args, ctx) {
  if (args.flags.help || args.flags.h) {
    _writeLine(ctx.stdout, AUDIT_USAGE);
    return 0;
  }
  if (args.pos.length === 0) {
    _writeLine(ctx.stderr, AUDIT_USAGE);
    return 2;
  }
  var sub = args.pos[0];
  var passphrase = _resolvePassphrase(args, ctx);
  // verify-chain reads the live DB, no bundle passphrase needed.
  var passRequired = sub === "archive" || sub === "export" ||
                     sub === "verify-bundle" || sub === "purge";
  if (passRequired && !passphrase) {
    _writeLine(ctx.stderr, "blamejs audit " + sub +
      ": --passphrase or BLAMEJS_AUDIT_PASSPHRASE is required");
    return 2;
  }

  if (sub === "archive") {
    var out    = _resolveOutPath(args.flags.out,    ctx);
    var before = args.flags.before;
    if (!out)    { _writeLine(ctx.stderr, "blamejs audit archive: --out is required"); return 2; }
    if (!before) { _writeLine(ctx.stderr, "blamejs audit archive: --before is required"); return 2; }
    try {
      var r = await auditTools.archive({
        before: before, out: out, passphrase: passphrase,
      });
      _writeLine(ctx.stdout, "wrote archive bundle to " + r.outDir +
        " (rowCount=" + r.rowCount +
        ", counters=" + r.range.firstCounter + ".." + r.range.lastCounter + ")");
      return 0;
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs audit archive: " + ((e && e.message) || String(e)));
      return 1;
    }
  }

  if (sub === "export") {
    var outE  = _resolveOutPath(args.flags.out, ctx);
    var from  = args.flags.from;
    var to    = args.flags.to;
    var action = args.flags.action;
    if (!outE) { _writeLine(ctx.stderr, "blamejs audit export: --out is required"); return 2; }
    if (!from && !to && !action) {
      _writeLine(ctx.stderr, "blamejs audit export: at least one of --from / --to / --action is required");
      return 2;
    }
    try {
      var r2 = await auditTools.exportSlice({
        from: from, to: to, action: action,
        out: outE, passphrase: passphrase,
      });
      _writeLine(ctx.stdout, "wrote export bundle to " + r2.outDir +
        " (rowCount=" + r2.rowCount +
        ", counters=" + r2.range.firstCounter + ".." + r2.range.lastCounter + ")");
      return 0;
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs audit export: " + ((e && e.message) || String(e)));
      return 1;
    }
  }

  if (sub === "verify-bundle") {
    var inV = _resolveOutPath(args.flags.in, ctx);
    if (!inV) { _writeLine(ctx.stderr, "blamejs audit verify-bundle: --in is required"); return 2; }
    try {
      var v = await auditTools.verifyBundle({ in: inV, passphrase: passphrase });
      if (v.ok) {
        _writeLine(ctx.stdout, "OK — bundle verified" +
          " (kind=" + v.kind +
          ", rowsVerified=" + v.rowsVerified +
          ", counters=" + v.range.firstCounter + ".." + v.range.lastCounter + ")");
        return 0;
      }
      _writeLine(ctx.stderr, "FAIL — " + v.reason);
      return 1;
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs audit verify-bundle: " + ((e && e.message) || String(e)));
      return 1;
    }
  }

  if (sub === "verify-chain") {
    var dbPathV = args.flags.db;
    if (!dbPathV || dbPathV === true) {
      _writeLine(ctx.stderr, "blamejs audit verify-chain: --db <path> is required");
      return 2;
    }
    dbPathV = _resolvePath(String(dbPathV), ctx.cwd);
    var tableV = args.flags.table ? String(args.flags.table) : "audit_log";
    var maxRows = args.flags["max-rows"];
    var maxRowsN = maxRows === undefined ? undefined : Number(maxRows);
    if (maxRowsN !== undefined && (!Number.isFinite(maxRowsN) || maxRowsN < 1)) {
      _writeLine(ctx.stderr, "blamejs audit verify-chain: --max-rows must be a positive integer");
      return 2;
    }
    var dbV;
    try { dbV = _openSqlite(dbPathV); }
    catch (e) {
      _writeLine(ctx.stderr, "blamejs audit verify-chain: cannot open db at " + dbPathV +
        ": " + ((e && e.message) || String(e)));
      return 1;
    }
    try {
      var queryAllAsync = async function (sql, params) {
        var stmt = dbV.prepare(sql);
        return Array.isArray(params) ? stmt.all.apply(stmt, params) : stmt.all();
      };
      var vc = await auditChain.verifyChain(queryAllAsync, tableV,
        maxRowsN ? { maxRows: maxRowsN } : {});
      if (vc.ok) {
        _writeLine(ctx.stdout, "OK — chain verified" +
          " (table=" + vc.table +
          ", rowsVerified=" + vc.rowsVerified + ")");
        return 0;
      }
      _writeLine(ctx.stderr, "FAIL — " + vc.reason +
        " (table=" + vc.table +
        ", rowsVerified=" + vc.rowsVerified +
        ", breakAt=" + vc.breakAt +
        ", breakRowId=" + vc.breakRowId + ")");
      _writeLine(ctx.stderr, "  expected prevHash: " + vc.expected);
      _writeLine(ctx.stderr, "  actual:            " + vc.actual);
      return 1;
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs audit verify-chain: " + ((e && e.message) || String(e)));
      return 1;
    } finally {
      try { dbV.close(); } catch (_e) { /* close best-effort */ }
    }
  }

  if (sub === "purge") {
    var inP = _resolveOutPath(args.flags.archive || args.flags.in, ctx);
    if (!inP) {
      _writeLine(ctx.stderr, "blamejs audit purge: --archive (path to verified archive bundle) is required");
      return 2;
    }
    if (args.flags.confirm !== true && args.flags.confirm !== "true") {
      _writeLine(ctx.stderr, "blamejs audit purge: --confirm is REQUIRED — destructive operation");
      return 2;
    }
    try {
      var p = await auditTools.purge({
        archive: inP, passphrase: passphrase, confirm: true,
      });
      _writeLine(ctx.stdout, "OK — purged " + p.rowsDeleted + " rows" +
        " (counters ≤ " + p.lastPurgedCounter + ")");
      return 0;
    } catch (e) {
      _writeLine(ctx.stderr, "blamejs audit purge: " + ((e && e.message) || String(e)));
      return 1;
    }
  }

  _writeLine(ctx.stderr, "blamejs audit: unknown subcommand '" + sub + "'");
  _writeLine(ctx.stderr, AUDIT_USAGE);
  return 2;
}

// ---- Subcommand: restore ----
//
// Operator workflow on top of b.restore: list bundles in storage,
// inspect a specific one, do a live in-place restore (with rollback
// preservation), and roll back to a previous restore point. Wraps the
// restore primitive's run / inspect / list / rollback / list-rollbacks
// surface; uses b.backup.diskStorage as the storage adapter (the same
// adapter that wrote the bundles).
//
// Two ways to identify a bundle for inspect / apply:
//   --bundle <dir>            point at an extracted bundle directory
//                             (parent dir is treated as storage root,
//                              dir basename as bundle id — matches the
//                              shape `blamejs backup extract` produces)
//   --storage-root <root> --bundle-id <id>   use a multi-bundle root

var RESTORE_USAGE = [
  "Usage: blamejs restore <subcommand> [flags]",
  "",
  "Subcommands:",
  "  list              List bundles available in storage",
  "  inspect           Read a bundle manifest summary (no live changes)",
  "  apply             Live in-place restore with rollback preserved",
  "  rollback          Revert the most-recent (or named) restore",
  "  list-rollbacks    List preserved rollback points",
  "",
  "Common flags:",
  "  --data-dir <path>      Live data directory (apply / rollback / list-rollbacks)",
  "  --storage-root <path>  Directory containing bundle subdirs (list)",
  "  --bundle <dir>         Extracted bundle directory (inspect / apply)",
  "  --bundle-id <id>       Alternative: pass id with --storage-root",
  "  --rollback-root <path> Override rollback dir (default <data-dir>.rollbacks)",
  "  --passphrase <string>  Bundle passphrase (or env BLAMEJS_BACKUP_PASSPHRASE)",
  "",
  "apply flags:",
  "  --max-pulled-bytes <N> Refuse a bundle whose pulled bytes exceed N (default 4 GiB)",
  "  --max-pulled-files <N> Refuse a bundle whose pulled file count exceeds N (default 100K)",
  "  --no-audit             Suppress audit emission (default ON)",
  "",
  "rollback flags:",
  "  --rollback <pathOrId>  Specific rollback point to restore (default: most recent)",
  "",
  "Exit codes:",
  "  0  success",
  "  1  operation failed",
  "  2  bad invocation",
].join("\n");

// Resolve {storageRoot, bundleId} from either --bundle <dir> OR
// --storage-root <root> --bundle-id <id>. Returns null + writes an
// error on the report when neither shape works.
function _resolveRestoreBundleSelector(args, ctx, report, requireBundle) {
  var bundleFlag = args.flags.bundle;
  var storageRootFlag = args.flags["storage-root"];
  var bundleIdFlag = args.flags["bundle-id"];
  if (bundleFlag && bundleFlag !== true) {
    var bundlePath = _resolvePath(String(bundleFlag), ctx.cwd);
    return {
      storageRoot: nodePath.dirname(bundlePath),
      bundleId:    nodePath.basename(bundlePath),
    };
  }
  if (storageRootFlag && storageRootFlag !== true) {
    var sr = _resolvePath(String(storageRootFlag), ctx.cwd);
    if (requireBundle) {
      if (!bundleIdFlag || bundleIdFlag === true) {
        report.error("--bundle-id is required when using --storage-root", 2);
        return null;
      }
      return { storageRoot: sr, bundleId: String(bundleIdFlag) };
    }
    return { storageRoot: sr, bundleId: null };
  }
  if (requireBundle) {
    report.error("--bundle <dir> OR --storage-root <root> --bundle-id <id> is required", 2);
  } else {
    report.error("--storage-root <root> is required", 2);
  }
  return null;
}

async function _runRestore(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs restore").usage(RESTORE_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs restore " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(RESTORE_USAGE);
  }
  if (["list", "inspect", "apply", "rollback", "list-rollbacks"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs restore").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs restore").usage(RESTORE_USAGE);
  }

  // list / inspect / apply all need a storage root + (for inspect/apply) a bundle id.
  // rollback / list-rollbacks only need data-dir.
  var dataDirFlag = args.flags["data-dir"];
  function _requireDataDir() {
    if (!dataDirFlag || dataDirFlag === true) {
      report.error("--data-dir <path> is required", 2);
      return null;
    }
    return _resolvePath(String(dataDirFlag), ctx.cwd);
  }

  if (sub === "list") {
    var sel = _resolveRestoreBundleSelector(args, ctx, report, false);
    if (!sel) return 2;
    try {
      var storage = backup.diskStorage({ root: sel.storageRoot });
      var bundles = await storage.listBundles();
      if (bundles.length === 0) {
        report.write("no bundles in " + sel.storageRoot);
        return report.ok();
      }
      report.write("bundles in " + sel.storageRoot + ": " + bundles.length);
      for (var i = 0; i < bundles.length; i++) {
        var b = bundles[i];
        report.write("  " + b.bundleId +
          "  size=" + (b.size != null ? b.size + "B" : "?") +
          "  createdAt=" + (b.createdAt || "?"));
      }
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  if (sub === "inspect") {
    var selI = _resolveRestoreBundleSelector(args, ctx, report, true);
    if (!selI) return 2;
    try {
      var storageI = backup.diskStorage({ root: selI.storageRoot });
      // restore.create needs a passphrase + dataDir even for inspect because
      // its closure captures them; pass placeholders since inspect doesn't
      // touch them.
      var rI = restore.create({
        dataDir: nodePath.join(os.tmpdir(), "blamejs-restore-inspect-noop"),
        storage: storageI,
        passphrase: "inspect-only-not-used",
        audit: false,
      });
      var manifest = await rI.inspect(selI.bundleId);
      var totalBytesI = 0;
      for (var ix = 0; ix < manifest.files.length; ix++) {
        totalBytesI += manifest.files[ix].encryptedSize || 0;
      }
      report.write("bundle:        " + selI.bundleId);
      report.write("storage root:  " + selI.storageRoot);
      report.write("manifest:      v" + (manifest.manifestVersion || manifest.version || "unknown"));
      report.write("created:       " + (manifest.createdAt || "unknown"));
      report.write("files:         " + manifest.files.length);
      report.write("encrypted size: " + totalBytesI + " bytes");
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  if (sub === "apply") {
    var dd = _requireDataDir();
    if (!dd) return 2;
    var selA = _resolveRestoreBundleSelector(args, ctx, report, true);
    if (!selA) return 2;
    var pp = cliHelpers.resolvePassphrase(args, ctx, {
      flag: "passphrase", envVar: "BLAMEJS_BACKUP_PASSPHRASE",
    });
    if (!pp) {
      return report.error("--passphrase or BLAMEJS_BACKUP_PASSPHRASE is required", 2);
    }
    var rollbackRootA = args.flags["rollback-root"]
      ? _resolvePath(String(args.flags["rollback-root"]), ctx.cwd) : undefined;
    var maxBytes = args.flags["max-pulled-bytes"];
    var maxFiles = args.flags["max-pulled-files"];
    if (maxBytes !== undefined && (!Number.isFinite(Number(maxBytes)) || Number(maxBytes) <= 0)) {
      return report.error("--max-pulled-bytes must be a positive number", 2);
    }
    if (maxFiles !== undefined && (!Number.isFinite(Number(maxFiles)) || Number(maxFiles) <= 0)) {
      return report.error("--max-pulled-files must be a positive number", 2);
    }
    try {
      var storageA = backup.diskStorage({ root: selA.storageRoot });
      var rA = restore.create({
        dataDir:         dd,
        storage:         storageA,
        passphrase:      pp,
        rollbackRoot:    rollbackRootA,
        audit:           args.flags["no-audit"] !== true,
        maxPulledBytes:  maxBytes !== undefined ? Number(maxBytes) : undefined,
        maxPulledFiles:  maxFiles !== undefined ? Number(maxFiles) : undefined,
      });
      var summary = await rA.run({ bundleId: selA.bundleId });
      report.write("OK — restored");
      report.write("  bundle:       " + summary.bundleId);
      report.write("  files:        " + summary.fileCount);
      report.write("  bytes:        " + summary.totalBytes);
      report.write("  rollback at:  " + summary.rollbackPath);
      report.write("  duration ms:  " + summary.durationMs);
      report.write("");
      report.write("Stop and start the app fresh against " + dd + " to pick up the restored state.");
      report.write("Roll back with: blamejs restore rollback --data-dir " + dd);
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  if (sub === "rollback") {
    var ddR = _requireDataDir();
    if (!ddR) return 2;
    var rollbackRootR = args.flags["rollback-root"]
      ? _resolvePath(String(args.flags["rollback-root"]), ctx.cwd)
      : (ddR + ".rollbacks");
    var rollbackTarget = args.flags.rollback;
    var targetPath = null;
    if (rollbackTarget && rollbackTarget !== true) {
      // operator can pass either a full path or just the basename inside rollback-root
      var rt = String(rollbackTarget);
      targetPath = nodePath.isAbsolute(rt) ? rt : nodePath.resolve(rollbackRootR, rt);
    } else {
      // Default to most-recent rollback point (mirrors restore.create().rollback()).
      var ptsR;
      try { ptsR = restoreRollback.list({ rollbackRoot: rollbackRootR }); }
      catch (e) {
        return report.error("listing rollbacks at " + rollbackRootR + ": " + ((e && e.message) || String(e)));
      }
      if (!ptsR || ptsR.length === 0) {
        return report.error("no rollback points at " + rollbackRootR + " — pass --rollback <pathOrId> explicitly", 2);
      }
      targetPath = ptsR[0].rollbackPath;
    }
    try {
      var rR = await restoreRollback.rollback({
        dataDir:      ddR,
        rollbackPath: targetPath,
        rollbackRoot: rollbackRootR,
      });
      report.write("OK — rolled back");
      report.write("  data dir:     " + ddR);
      report.write("  used:         " + (targetPath || "most-recent rollback point"));
      report.write("  discarded at: " + (rR.discardedAt || "(unknown)"));
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  if (sub === "list-rollbacks") {
    var ddL = _requireDataDir();
    if (!ddL) return 2;
    var rollbackRootL = args.flags["rollback-root"]
      ? _resolvePath(String(args.flags["rollback-root"]), ctx.cwd)
      : (ddL + ".rollbacks");
    try {
      var pts = restoreRollback.list({ rollbackRoot: rollbackRootL });
      if (pts.length === 0) {
        report.write("no rollback points at " + rollbackRootL);
        return report.ok();
      }
      report.write("rollback points at " + rollbackRootL + ": " + pts.length);
      for (var p = 0; p < pts.length; p++) {
        var pt = pts[p];
        report.write("  " + (pt.rollbackPath || pt) +
          (pt.recordedAt ? "  recordedAt=" + pt.recordedAt : "") +
          (pt.bundleId ? "  bundleId=" + pt.bundleId : ""));
      }
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  return 2;
}

// ---- Top-level help ----

// ---- Subcommand: api-key ----

var API_KEY_USAGE = [
  "Usage: blamejs api-key <subcommand> [flags]",
  "",
  "Subcommands:",
  "  issue             Issue a new API key under a namespace. Prints the",
  "                    composite key + id. The plaintext secret is shown",
  "                    ONCE and cannot be recovered after the command exits.",
  "  revoke            Revoke an issued key by its composite id (namespace:idHex).",
  "  list              List active keys for a given owner under a namespace.",
  "  rotate            Issue a new secret for an existing id while leaving the",
  "                    old secret valid for opts.gracePeriodMs (default 0 — immediate).",
  "  verify            Verify a token string and print the resolved metadata.",
  "                    Useful for debugging an integration that's seeing 401s.",
  "",
  "Flags (all subcommands):",
  "  --data-dir <path>      Path to the app's data dir (required)",
  "  --namespace <name>     API-key namespace (required) — typically matches the",
  "                         operator's b.apiKey.create({ namespace }) at boot",
  "  --vault-mode <mode>    plaintext | wrapped (default wrapped). When wrapped,",
  "                         BLAMEJS_VAULT_PASSPHRASE must be set.",
  "",
  "Subcommand flags:",
  "  issue:   --owner-id <id>   --scopes <comma-separated>   [--label <text>]   [--expires-ms <ms>]",
  "  revoke:  --id <idHex>",
  "  list:    --owner-id <id>",
  "  rotate:  --id <idHex>   [--grace-ms <ms>]",
  "  verify:  --token <key>",
].join("\n");

async function _runApiKey(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs api-key").usage(API_KEY_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs api-key " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(API_KEY_USAGE);
  }
  if (["issue", "revoke", "list", "rotate", "verify"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs api-key").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs api-key").usage(API_KEY_USAGE);
  }

  var dataDirFlag = args.flags["data-dir"];
  if (!dataDirFlag || dataDirFlag === true) {
    return report.error("--data-dir <path> is required", 2);
  }
  var dataDir = _resolvePath(String(dataDirFlag), ctx.cwd);

  var namespace = args.flags.namespace;
  if (!namespace || namespace === true) {
    return report.error("--namespace <name> is required", 2);
  }
  namespace = String(namespace);

  var vaultMode = args.flags["vault-mode"] || "wrapped";
  if (vaultMode !== "wrapped" && vaultMode !== "plaintext") {
    return report.error("--vault-mode must be 'wrapped' or 'plaintext'", 2);
  }

  var booted;
  try {
    booted = await cliHelpers.bootApp({
      dataDir:   dataDir,
      vaultMode: vaultMode,
      env:       ctx.env,
    });
  } catch (e) {
    return report.error("boot failed: " + ((e && e.message) || String(e)));
  }

  try {
    var registry = booted.b.apiKey.create({
      namespace: namespace,
      audit:     booted.b.audit,
    });

    if (sub === "issue") {
      var ownerId = args.flags["owner-id"];
      var scopes  = args.flags.scopes;
      if (!ownerId || ownerId === true) return report.error("--owner-id <id> is required", 2);
      if (!scopes  || scopes === true)  return report.error("--scopes <comma-separated> is required", 2);
      var scopeList = requestHelpers.parseListHeader(scopes);
      if (scopeList.length === 0) {
        return report.error("--scopes must contain at least one non-empty scope", 2);
      }
      var label = typeof args.flags.label === "string" ? args.flags.label : null;
      // --expires-ms is the absolute expiry as a unix-ms timestamp; the
      // registry's validated opt is `expiresAt` (apiKey.issue rejects any other
      // key). Passing `expiresMs` silently did nothing before — the lib only
      // ever read `expiresAt` — so the flag was a no-op; map it correctly.
      var expiresMs = args.flags["expires-ms"];
      var issued = await registry.issue({
        ownerId:   String(ownerId),
        scopes:    scopeList,
        metadata:  label ? { label: label } : null,
        expiresAt: expiresMs && expiresMs !== true ? Number(expiresMs) : undefined,
      });
      report.write("id:     " + issued.id);
      report.write("key:    " + issued.key);
      report.write("scopes: " + issued.scopes.join(", "));
      if (issued.expiresAt) report.write("expires: " + new Date(issued.expiresAt).toISOString());
      return report.ok("\nThe plaintext secret is shown ONCE — copy it now.");
    }

    if (sub === "revoke") {
      var revokeId = args.flags.id;
      if (!revokeId || revokeId === true) return report.error("--id <idHex> is required", 2);
      var revoked = await registry.revoke(String(revokeId));
      return revoked
        ? report.ok("revoked: " + revokeId)
        : report.error("no-op: " + revokeId + " not found or already revoked");
    }

    if (sub === "list") {
      var listOwnerId = args.flags["owner-id"];
      if (!listOwnerId || listOwnerId === true) return report.error("--owner-id <id> is required", 2);
      var rows = await registry.listForOwner(String(listOwnerId));
      report.write("owner: " + listOwnerId + " (" + rows.length + " active keys)");
      for (var i = 0; i < rows.length; i++) {
        var r = rows[i];
        var scope = Array.isArray(r.scopes) ? r.scopes.join(",") : "";
        report.write("  " + r.id + "  scopes=[" + scope + "]" +
          (r.expiresAt ? "  expires=" + new Date(r.expiresAt).toISOString() : ""));
      }
      return report.ok();
    }

    if (sub === "rotate") {
      var rotateId = args.flags.id;
      if (!rotateId || rotateId === true) return report.error("--id <idHex> is required", 2);
      var graceMs = args.flags["grace-ms"];
      var rotated = await registry.rotate(String(rotateId), {
        gracePeriodMs: graceMs && graceMs !== true ? Number(graceMs) : 0,
      });
      report.write("id:        " + rotated.id);
      report.write("key (new): " + rotated.key);
      return report.ok("\nUpdate your integration to the new key, then revoke the old secret " +
        "(or wait gracePeriodMs for it to expire).");
    }

    if (sub === "verify") {
      var token = args.flags.token;
      if (!token || token === true) return report.error("--token <key> is required", 2);
      var v = await registry.verify(String(token));
      if (!v) return report.error("rejected: token does not verify (bad format, unknown id, revoked, or expired)");
      report.write("id:       " + v.id);
      report.write("ownerId:  " + v.ownerId);
      report.write("scopes:   " + (v.scopes || []).join(", "));
      if (v.lastUsedAt) report.write("last-used: " + new Date(v.lastUsedAt).toISOString());
      if (v.expiresAt)  report.write("expires:   " + new Date(v.expiresAt).toISOString());
      return report.ok();
    }

    return 2;
  } catch (e) {
    return report.error((e && e.message) || String(e));
  } finally {
    try { await booted.app.shutdown(); } catch (_e) { /* best-effort */ }
  }
}

// ---- Subcommand: backup ----

var BACKUP_USAGE = [
  "Usage: blamejs backup <subcommand> [flags]",
  "",
  "Subcommands:",
  "  inspect           Read a bundle's manifest without decrypting and",
  "                    print a summary (file count, total bytes, kinds,",
  "                    timestamp). No passphrase required — useful for",
  "                    pre-flight before a restore.",
  "  verify            Decrypt + verify the bundle in a temp directory,",
  "                    discard the output. Confirms passphrase is correct",
  "                    and every encrypted blob's HMAC validates against",
  "                    the manifest, without committing a restore.",
  "  extract           Decrypt + verify into the target staging directory.",
  "                    The staging directory is the operator's responsibility",
  "                    to inspect and then move into place; this command",
  "                    never touches the live data dir.",
  "",
  "Flags:",
  "  --bundle <dir>         Path to a bundle directory (must contain manifest.json)",
  "  --to <stagingDir>      For extract — fresh directory to decrypt into (must not exist)",
  "  --passphrase <string>  Backup passphrase (or env BLAMEJS_BACKUP_PASSPHRASE)",
].join("\n");

async function _runBackup(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs backup").usage(BACKUP_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs backup " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(BACKUP_USAGE);
  }
  if (["inspect", "verify", "extract"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs backup").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs backup").usage(BACKUP_USAGE);
  }

  var bundleFlag = args.flags.bundle;
  if (!bundleFlag || bundleFlag === true) {
    return report.error("--bundle <dir> is required", 2);
  }
  var bundleDir = _resolvePath(String(bundleFlag), ctx.cwd);

  if (sub === "inspect") {
    try {
      var m = restoreBundle.inspect({ bundleDir: bundleDir });
      var totalBytes = 0;
      for (var i = 0; i < m.files.length; i++) totalBytes += m.files[i].encryptedSize || 0;
      report.write("bundle:        " + bundleDir);
      report.write("manifest:      v" + (m.manifestVersion || m.version || "unknown"));
      report.write("created:       " + (m.createdAt || "unknown"));
      report.write("files:         " + m.files.length);
      report.write("encrypted size: " + totalBytes + " bytes");
      var kinds = {};
      for (var k = 0; k < m.files.length; k++) {
        var kind = m.files[k].kind || "unknown";
        kinds[kind] = (kinds[kind] || 0) + 1;
      }
      // Stable kind ordering for the human-readable report — same
      // sort the framework's canonical-json walker uses for object
      // keys. Pulled out as a sortKeys() helper so this single sorted
      // walk in cli matches the canonical-json discipline elsewhere.
      var ks = canonicalJson.sortKeys(kinds);
      for (var ki = 0; ki < ks.length; ki++) {
        report.write("  " + ks[ki] + ": " + kinds[ks[ki]]);
      }
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  // verify + extract both decrypt — both need a passphrase.
  var pp = cliHelpers.resolvePassphrase(args, ctx, {
    flag: "passphrase", envVar: "BLAMEJS_BACKUP_PASSPHRASE",
  });
  if (!pp) {
    return report.error("--passphrase or BLAMEJS_BACKUP_PASSPHRASE is required", 2);
  }

  if (sub === "verify") {
    var stagingDir = nodePath.join(os.tmpdir(),
      "blamejs-backup-verify-" + bCrypto.generateToken(C.BYTES.bytes(8)));
    try {
      var r = await restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: stagingDir,
        passphrase: pp,
      });
      report.write("verified: " + (r && r.fileCount != null ? r.fileCount : "n/a") + " files");
      report.write("passphrase decrypts the vault-key wrap");
      report.write("every blob's HMAC validates against the manifest");
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    } finally {
      try { nodeFs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
    }
  }

  if (sub === "extract") {
    var toFlag = args.flags.to;
    if (!toFlag || toFlag === true) {
      return report.error("--to <stagingDir> is required", 2);
    }
    var stagingDir2 = _resolvePath(String(toFlag), ctx.cwd);
    try {
      var rr = await restoreBundle.extract({
        bundleDir:  bundleDir,
        stagingDir: stagingDir2,
        passphrase: pp,
      });
      report.write("extracted: " + (rr && rr.fileCount != null ? rr.fileCount : "n/a") +
        " files → " + stagingDir2);
      report.write("");
      report.write("Inspect the staging directory before moving any files into your live data dir.");
      report.write("blamejs does NOT auto-promote — that's an operator decision.");
      return report.ok();
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  return 2;
}

// ---- Subcommand: mtls ----

var MTLS_USAGE = [
  "Usage: blamejs mtls <subcommand> [flags]",
  "",
  "Subcommands:",
  "  status            Print CA state — exists / generation / sealed-mode.",
  "                    No engine required.",
  "  show-cert         Print the CA certificate PEM to stdout. Operators",
  "                    paste this into client truststores. No engine required.",
  "  init              Generate a fresh CA keypair + self-signed cert and",
  "                    write to data-dir. Requires opts.engine — see note below.",
  "  issue             Issue a leaf client certificate signed by the CA.",
  "                    Requires opts.engine + --subject. Prints cert + key PEM.",
  "  issue-p12         Issue + package as PKCS#12 with --password. Useful for",
  "                    importing into browsers / OS keychains. Requires engine.",
  "",
  "Flags:",
  "  --data-dir <path>      Path to the app's data dir (required)",
  "  --vault-mode <mode>    plaintext | wrapped (default wrapped). When wrapped,",
  "                         BLAMEJS_VAULT_PASSPHRASE must be set.",
  "  --sealed-mode <mode>   auto | required | disabled (default auto). 'required'",
  "                         seals the CA key under the vault before writing it",
  "                         to disk; 'disabled' keeps it plaintext on disk;",
  "                         'auto' loads whichever form exists.",
  "",
  "Subcommand flags:",
  "  issue:     --subject <CN>    [--days <N>]",
  "  issue-p12: --subject <CN>    --password <pkcs12-passphrase>    [--days <N>]    [--out <path>]",
  "",
  "Cert issuance ('init', 'issue', 'issue-p12') uses the framework's",
  "bundled pure-JS engine (lib/mtls-engine-default.js, ECDSA P-384",
  "signatures, AES-256-CBC + HMAC-SHA-512 PBKDF2 PKCS#12 with 2,000,000",
  "iterations). Operators with custom requirements pass a different",
  "engine via b.mtlsCa.create({ engine: ... }) when wiring their app;",
  "the CLI always uses the default.",
].join("\n");

async function _runMtls(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs mtls").usage(MTLS_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs mtls " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(MTLS_USAGE);
  }
  if (["status", "show-cert", "init", "issue", "issue-p12"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs mtls").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs mtls").usage(MTLS_USAGE);
  }

  var dataDirFlag = args.flags["data-dir"];
  if (!dataDirFlag || dataDirFlag === true) {
    return report.error("--data-dir <path> is required", 2);
  }
  var dataDir = _resolvePath(String(dataDirFlag), ctx.cwd);

  var vaultMode = args.flags["vault-mode"] || "wrapped";
  if (vaultMode !== "wrapped" && vaultMode !== "plaintext") {
    return report.error("--vault-mode must be 'wrapped' or 'plaintext'", 2);
  }
  var sealedMode = args.flags["sealed-mode"] || "required";
  if (["required", "disabled"].indexOf(sealedMode) === -1) {
    return report.error("--sealed-mode must be 'required' or 'disabled'", 2);
  }

  var booted;
  try {
    booted = await cliHelpers.bootApp({
      dataDir:   dataDir,
      vaultMode: vaultMode,
      env:       ctx.env,
    });
  } catch (e) {
    return report.error("boot failed: " + ((e && e.message) || String(e)));
  }

  try {
    var ca = booted.b.mtlsCa.create({
      dataDir:         dataDir,
      vault:           booted.b.vault,
      caKeySealedMode: sealedMode,
      // No engine passed — b.mtlsCa falls back to the bundled default
      // (lib/mtls-engine-default.js).
    });

    if (sub === "status") {
      var s = ca.status();
      report.write("data-dir:    " + dataDir);
      report.write("CA exists:   " + (s.exists ? "yes" : "no"));
      if (s.exists) {
        report.write("generation:  " + s.generation +
          (s.isLegacy ? " (LEGACY — current is " + s.current + ", rotate via init)" : ""));
        report.write("ca-key-sealed-mode: " + ca.caKeySealedMode);
        report.write("paths:");
        report.write("  cert:       " + ca.paths.caCert);
        report.write("  key:        " + ca.paths.caKey);
        report.write("  key-sealed: " + ca.paths.caKeySealed);
      } else {
        report.write("(run 'blamejs mtls init' to generate a CA)");
      }
      return report.ok();
    }

    if (sub === "show-cert") {
      if (!ca.exists()) {
        return report.error("no CA on disk at " + ca.paths.caCert + " — run 'blamejs mtls init' first");
      }
      try {
        var pem = ca.loadCert().toString("utf8");
        report.write(pem.trim());
        return report.ok();
      } catch (e) {
        return report.error("could not load CA cert: " + ((e && e.message) || String(e)));
      }
    }

    if (sub === "init") {
      try {
        await ca.initCA();
        report.write("ca-cert:     " + ca.paths.caCert);
        report.write("ca-key:      " + (ca.caKeySealedMode === "required" ? ca.paths.caKeySealed : ca.paths.caKey));
        return report.ok("CA generated. Distribute ca-cert to clients via 'blamejs mtls show-cert'.");
      } catch (e) {
        return report.error((e && e.message) || String(e));
      }
    }

    if (sub === "issue") {
      var subject = args.flags.subject;
      if (!subject || subject === true) return report.error("--subject <CN> is required", 2);
      var days = args.flags.days && args.flags.days !== true ? Number(args.flags.days) : undefined;
      try {
        var leaf = await ca.generateClientCert({ cn: String(subject), validityDays: days });
        report.write("# certificate");
        report.write(leaf.cert.trim());
        report.write("");
        report.write("# private key");
        report.write(leaf.key.trim());
        // Framework-canonical fingerprint via b.crypto.sha3Hash. Computed
        // here over the leaf cert PEM bytes so the audit trail is
        // independent of whatever fingerprint format the operator-
        // supplied engine returns. Operators wanting the X.509-
        // conventional SHA-256 fingerprint (browsers, openssl) can run
        // `openssl x509 -fingerprint -sha256 -in cert.pem` separately.
        report.write("");
        report.write("# fingerprint (sha3-512): " + booted.b.crypto.sha3Hash(Buffer.from(leaf.cert, "utf8")));
        if (leaf.expiresAt) report.write("# expires: " + new Date(leaf.expiresAt).toISOString());
        return report.ok();
      } catch (e) {
        return report.error((e && e.message) || String(e));
      }
    }

    if (sub === "issue-p12") {
      var subjectP = args.flags.subject;
      var password = args.flags.password;
      if (!subjectP || subjectP === true) return report.error("--subject <CN> is required", 2);
      if (!password || password === true) return report.error("--password <pkcs12-passphrase> is required", 2);
      var daysP = args.flags.days && args.flags.days !== true ? Number(args.flags.days) : undefined;
      var outPath = args.flags.out && args.flags.out !== true
        ? _resolvePath(String(args.flags.out), ctx.cwd)
        : null;
      try {
        var p12 = await ca.generateClientP12({
          cn:           String(subjectP),
          password:     String(password),
          validityDays: daysP,
        });
        if (outPath) {
          // Atomic, symlink-refusing write — a bare writeFileSync follows a
          // symlink an attacker pre-planted at the operator-supplied --out
          // path (CWE-59) and could expose the client key bundle through it.
          atomicFile.writeSync(outPath, p12.p12, { fileMode: 0o600 });
          report.write("p12 written: " + outPath);
        } else {
          // No --out: stream the bytes to stdout for piping. Operators
          // can `blamejs mtls issue-p12 ... > client.p12`.
          if (ctx.stdout && typeof ctx.stdout.write === "function") {
            ctx.stdout.write(p12.p12);
          }
        }
        // Framework-canonical fingerprint via b.crypto.sha3Hash over
        // the embedded cert PEM, same posture as the issue path above.
        // Independent of the engine's fingerprint format.
        if (p12.certPem) {
          report.write("# fingerprint (sha3-512): " + booted.b.crypto.sha3Hash(Buffer.from(p12.certPem, "utf8")));
        }
        if (p12.expiresAt) report.write("# expires: " + new Date(p12.expiresAt).toISOString());
        return report.ok();
      } catch (e) {
        return report.error((e && e.message) || String(e));
      }
    }

    return 2;
  } finally {
    try { await booted.app.shutdown(); } catch (_e) { /* best-effort */ }
  }
}

// ---- Subcommand: vault ----

var VAULT_USAGE = [
  "Usage: blamejs vault <subcommand> [flags]",
  "",
  "Subcommands:",
  "  status            Report whether vault.key (plaintext) and/or",
  "                    vault.key.sealed (wrapped) exist under <data-dir>",
  "  seal              Wrap a plaintext vault.key into a passphrase-",
  "                    sealed vault.key.sealed (Argon2id KDF +",
  "                    XChaCha20-Poly1305). Crash-safe: writes to .tmp",
  "                    + fsync + atomic rename, leaves the original",
  "                    untouched on any failure.",
  "  unseal            Reverse — write a plaintext vault.key from a",
  "                    sealed file. For audits / migration to a new",
  "                    machine; remove the plaintext file as soon as",
  "                    you're done.",
  "  rotate            Re-wrap a sealed vault.key.sealed under a new",
  "                    passphrase. The old passphrase is required to",
  "                    unwrap; the new passphrase wraps. The keypair",
  "                    itself is unchanged (use `b.vault.rotateKey()`",
  "                    at runtime if you want to rotate the keypair).",
  "",
  "Flags:",
  "  --data-dir <path>      Path to the app's data dir (default ./data)",
  "  --passphrase <string>  Passphrase to wrap with (or env",
  "                         BLAMEJS_VAULT_PASSPHRASE). For `rotate`,",
  "                         this is the OLD passphrase; pair with",
  "                         --new-passphrase / BLAMEJS_VAULT_PASSPHRASE_NEW.",
  "  --new-passphrase <s>   Rotate-only — the NEW passphrase to re-wrap",
  "                         under. Or env BLAMEJS_VAULT_PASSPHRASE_NEW.",
  "  --keep-plaintext       For `seal` — retain the plaintext vault.key",
  "                         file (default: delete it after sealing).",
].join("\n");

async function _runVault(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs vault").usage(VAULT_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs vault " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(VAULT_USAGE);
  }
  if (["status", "seal", "unseal", "rotate"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs vault").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs vault").usage(VAULT_USAGE);
  }

  var dataDir = _resolvePath(String(args.flags["data-dir"] || "./data"), ctx.cwd);

  if (sub === "status") {
    var pre = vaultPassphraseOps.preflightSealable({ dataDir: dataDir });
    var unsealable = vaultPassphraseOps.preflightUnsealable
      ? vaultPassphraseOps.preflightUnsealable({ dataDir: dataDir })
      : null;
    report.write("data-dir: " + dataDir);
    report.write("vault.key (plaintext):    " +
      (pre.ok ? "present (sealable)" : "absent — " + (pre.reason || "n/a")));
    if (unsealable) {
      report.write("vault.key.sealed (wrapped): " +
        (unsealable.ok ? "present" : "absent — " + (unsealable.reason || "n/a")));
    }
    return report.ok();
  }

  if (sub === "seal") {
    var pp = cliHelpers.resolvePassphrase(args, ctx, {
      flag: "passphrase", envVar: "BLAMEJS_VAULT_PASSPHRASE",
    });
    if (!pp) {
      return report.error("--passphrase or BLAMEJS_VAULT_PASSPHRASE is required", 2);
    }
    try {
      var r = await vaultPassphraseOps.seal({
        dataDir:        dataDir,
        passphrase:     pp,
        keepPlaintext:  !!args.flags["keep-plaintext"],
      });
      report.write("sealed: " + r.sealedPath);
      report.write(r.plaintextDeleted
        ? "removed plaintext vault.key"
        : "kept plaintext vault.key (--keep-plaintext set)");
      report.write("");
      report.write("Set BLAMEJS_VAULT_PASSPHRASE in the runtime environment and");
      return report.ok("boot the app with vault: { mode: \"wrapped\" }.");
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  if (sub === "unseal") {
    var pp2 = cliHelpers.resolvePassphrase(args, ctx, {
      flag: "passphrase", envVar: "BLAMEJS_VAULT_PASSPHRASE",
    });
    if (!pp2) {
      return report.error("--passphrase or BLAMEJS_VAULT_PASSPHRASE is required", 2);
    }
    try {
      var u = await vaultPassphraseOps.unseal({ dataDir: dataDir, passphrase: pp2 });
      report.write("unsealed: " + u.plaintextPath);
      report.write("");
      report.write("WARNING: vault.key is now plaintext on disk. Re-seal as soon");
      return report.ok("as you're done auditing or migrating.");
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  if (sub === "rotate") {
    var oldPp = cliHelpers.resolvePassphrase(args, ctx, {
      flag: "passphrase", envVar: "BLAMEJS_VAULT_PASSPHRASE",
    });
    var newPp = cliHelpers.resolvePassphrase(args, ctx, {
      flag: "new-passphrase", envVar: "BLAMEJS_VAULT_PASSPHRASE_NEW",
    });
    if (!oldPp || !newPp) {
      report.error("both --passphrase (old) and --new-passphrase are required", 2);
      report.writeErr("(or BLAMEJS_VAULT_PASSPHRASE + BLAMEJS_VAULT_PASSPHRASE_NEW)");
      return 2;
    }
    try {
      var rr = await vaultPassphraseOps.rotate({
        dataDir:        dataDir,
        oldPassphrase:  oldPp,
        newPassphrase:  newPp,
      });
      report.write("rotated: " + rr.sealedPath);
      return report.ok("Update BLAMEJS_VAULT_PASSPHRASE in the runtime environment to the new value.");
    } catch (e) {
      return report.error((e && e.message) || String(e));
    }
  }

  return 2;
}

// ---- Subcommand: security ----------------------------------------
//
// Runs b.security.assertProduction against the live framework. Useful
// out-of-band: ops can re-check posture without rebooting the app.
// Boots the framework so resolvers see the actual vault / db / audit-
// signing modes; reports pass / fail with the failure-code list.

var SECURITY_USAGE = [
  "Usage: blamejs security <subcommand> [flags]",
  "",
  "Subcommands:",
  "  assert            Run b.security.assertProduction against the framework's",
  "                    live posture (vault / dbAtRest / auditSigning / NTP / env",
  "                    vars / dataDir POSIX-mode / NODE_ENV). Exit 0 = clean,",
  "                    exit 1 = one or more assertions failed.",
  "",
  "Flags:",
  "  --data-dir <path>            Required for `assert` (the boot dir)",
  "  --vault-mode <mode>          plaintext | wrapped (default wrapped)",
  "  --no-ntp-strict              Skip the BLAMEJS_NTP_STRICT check",
  "  --require-env <KEY,KEY,...>  Comma-separated env vars that MUST be set",
  "  --forbid-env  <KEY,KEY,...>  Comma-separated env vars that must NOT be set",
  "  --no-vault                   Skip vault posture check",
  "  --no-db-at-rest              Skip dbAtRest posture check",
  "  --no-audit-signing           Skip auditSigning posture check",
].join("\n");

async function _runSecurity(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs security").usage(SECURITY_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs security " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(SECURITY_USAGE);
  }
  if (sub !== "assert") {
    cliHelpers.makeReporter(ctx, "blamejs security").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs security").usage(SECURITY_USAGE);
  }
  var dataDirFlag = args.flags["data-dir"];
  if (!dataDirFlag || dataDirFlag === true) {
    return report.error("--data-dir <path> is required", 2);
  }
  var dataDir = _resolvePath(String(dataDirFlag), ctx.cwd);
  var vaultMode = args.flags["vault-mode"] || "wrapped";
  if (vaultMode !== "wrapped" && vaultMode !== "plaintext") {
    return report.error("--vault-mode must be 'wrapped' or 'plaintext'", 2);
  }
  var booted;
  try {
    booted = await cliHelpers.bootApp({ dataDir: dataDir, vaultMode: vaultMode, env: ctx.env });
  } catch (e) {
    return report.error("boot failed: " + ((e && e.message) || String(e)));
  }
  try {
    var assertOpts = {
      audit:        booted.b.audit,
      dataDir:      dataDir,
      vault:        args.flags["no-vault"]         ? false : "wrapped",
      dbAtRest:     args.flags["no-db-at-rest"]    ? false : "encrypted",
      auditSigning: args.flags["no-audit-signing"] ? false : "wrapped",
      ntpStrict:    !args.flags["no-ntp-strict"],
    };
    if (args.flags["require-env"] && args.flags["require-env"] !== true) {
      assertOpts.requireEnv = requestHelpers.parseListHeader(args.flags["require-env"]);
    }
    if (args.flags["forbid-env"] && args.flags["forbid-env"] !== true) {
      assertOpts.forbidEnv = requestHelpers.parseListHeader(args.flags["forbid-env"]);
    }
    try {
      await booted.b.security.assertProduction(assertOpts);
      return report.ok("production posture clean");
    } catch (e) {
      if (e && e.isSecurityAssertError && Array.isArray(e.failures)) {
        report.write("FAIL: " + e.failures.length + " assertion(s):");
        for (var fi = 0; fi < e.failures.length; fi++) {
          report.write("  - " + e.failures[fi].code + ": " + e.failures[fi].message);
        }
        return 1;
      }
      return report.error((e && e.message) || String(e));
    }
  } finally {
    try { await booted.app.shutdown(); } catch (_e) { /* best-effort */ }
  }
}

// ---- Subcommand: config-drift -------------------------------------
//
// Inspect / verify the b.configDrift sidecar without rebooting. The
// sidecar is signed with the audit-signing key, so we boot the
// framework to access it. `inspect` prints the full snapshot;
// `verify` only reports the verified flag (exit 0 = signed +
// untampered, exit 1 = tampered or missing).

var CONFIG_DRIFT_USAGE = [
  "Usage: blamejs config-drift <subcommand> [flags]",
  "",
  "Subcommands:",
  "  inspect           Print the sidecar's snapshot + capturedAt + verified flag",
  "  verify            Verify the sidecar's signature (exit code reflects status)",
  "",
  "Flags:",
  "  --data-dir <path>      Required (sidecar location)",
  "  --baseline <name>      Multi-baseline name (default: \"default\")",
  "  --vault-mode <mode>    plaintext | wrapped (default wrapped)",
  "  --json                 inspect: print machine-readable JSON",
].join("\n");

async function _runConfigDrift(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs config-drift").usage(CONFIG_DRIFT_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs config-drift " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(CONFIG_DRIFT_USAGE);
  }
  if (["inspect", "verify"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs config-drift").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs config-drift").usage(CONFIG_DRIFT_USAGE);
  }
  var dataDirFlag = args.flags["data-dir"];
  if (!dataDirFlag || dataDirFlag === true) {
    return report.error("--data-dir <path> is required", 2);
  }
  var dataDir = _resolvePath(String(dataDirFlag), ctx.cwd);
  var vaultMode = args.flags["vault-mode"] || "wrapped";
  var booted;
  try {
    booted = await cliHelpers.bootApp({ dataDir: dataDir, vaultMode: vaultMode, env: ctx.env });
  } catch (e) {
    return report.error("boot failed: " + ((e && e.message) || String(e)));
  }
  try {
    var driftOpts = { dataDir: dataDir, audit: booted.b.audit };
    if (args.flags.baseline && args.flags.baseline !== true) {
      driftOpts.baseline = String(args.flags.baseline);
    }
    var drift = booted.b.configDrift.create(driftOpts);
    var sidecar = drift.read();
    if (!sidecar) {
      report.write("no sidecar present at " + drift.sidecarPath);
      return sub === "verify" ? 1 : 0;
    }
    if (sub === "verify") {
      if (sidecar.verified) {
        return report.ok("sidecar verified at " + new Date(sidecar.capturedAt).toISOString());
      }
      report.error("sidecar tamper detected: " + sidecar.tamperReason);
      return 1;
    }
    if (args.flags.json) {
      report.write(JSON.stringify({
        capturedAt:    sidecar.capturedAt,
        digestHex:     sidecar.digestHex,
        verified:      sidecar.verified,
        tamperReason:  sidecar.tamperReason,
        snapshot:      sidecar.snapshot,
      }, null, 2));
    } else {
      report.write("sidecar:    " + drift.sidecarPath);
      report.write("capturedAt: " + new Date(sidecar.capturedAt).toISOString());
      report.write("digestHex:  " + sidecar.digestHex);
      report.write("verified:   " + (sidecar.verified ? "yes" : "no — " + sidecar.tamperReason));
      report.write("snapshot:");
      report.write(JSON.stringify(sidecar.snapshot, null, 2));
    }
    return sidecar.verified ? 0 : 1;
  } finally {
    try { await booted.app.shutdown(); } catch (_e) { /* best-effort */ }
  }
}

// ---- Subcommand: file-type ---------------------------------------
//
// Pure utility — magic-byte content classification. No framework
// boot. Useful for upload debugging ("the user said this was a PDF
// but is it really?") and as a CI-side sanity check.

var FILE_TYPE_USAGE = [
  "Usage: blamejs file-type detect <file> [flags]",
  "",
  "Inspects the leading bytes of <file> against the b.fileType signature",
  "registry. Prints the detected mime / extension / category; exit 1 when",
  "no signature matches (the actual format is unknown to the registry).",
  "",
  "Flags:",
  "  --json                 Print machine-readable JSON",
  "  --allowlist <list>     Comma-separated mime / category list — exits 1",
  "                         when the detected type is NOT in the allowlist",
  "                         (mirrors b.fileType.assertOneOf).",
].join("\n");

function _runFileType(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs file-type").usage(FILE_TYPE_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs file-type " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(FILE_TYPE_USAGE);
  }
  if (sub !== "detect") {
    cliHelpers.makeReporter(ctx, "blamejs file-type").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs file-type").usage(FILE_TYPE_USAGE);
  }
  var file = args.pos[1];
  if (!file) return report.error("file path is required (positional arg after 'detect')", 2);
  var resolved = _resolvePath(String(file), ctx.cwd);
  var buf;
  try { buf = nodeFs.readFileSync(resolved); }
  catch (e) {
    return report.error("read failed: " + ((e && e.message) || String(e)));
  }
  if (args.flags.allowlist && args.flags.allowlist !== true) {
    var allowed = requestHelpers.parseListHeader(args.flags.allowlist);
    try {
      var det = fileType.assertOneOf(buf, allowed);
      if (args.flags.json) report.write(JSON.stringify(det));
      else {
        report.write("mime:      " + det.mime);
        report.write("extension: " + det.extension);
        report.write("category:  " + det.category);
        report.write("name:      " + det.name);
      }
      return report.ok("matched allowlist " + JSON.stringify(allowed));
    } catch (e) {
      return report.error(e.code + ": " + e.message);
    }
  }
  var detected = fileType.detect(buf);
  if (!detected) {
    if (args.flags.json) report.write("null");
    return report.error("unknown — no signature matched the leading bytes (" +
      buf.length + " bytes read)");
  }
  if (args.flags.json) {
    report.write(JSON.stringify(detected));
  } else {
    report.write("mime:      " + detected.mime);
    report.write("extension: " + detected.extension);
    report.write("category:  " + detected.category);
    report.write("name:      " + detected.name);
  }
  return report.ok();
}

// ---- Subcommand: password ----------------------------------------
//
// Test b.auth.password.policy from the CLI without rebooting the app.
// Useful for ops dashboards that want to surface "your policy
// requires X" or for CI checks of operator-supplied passwords.

var PASSWORD_USAGE = [
  "Usage: blamejs password check [flags]",
  "",
  "Runs b.auth.password.policy({ profile, ... }).check(plaintext, context).",
  "Exit 0 = ok, exit 1 = policy rejected, exit 2 = bad args.",
  "",
  "Flags:",
  "  --plaintext <s>        REQUIRED — the plaintext to test (or use stdin)",
  "  --stdin                Read the plaintext from stdin (newline-trimmed)",
  "  --profile <name>       Named profile: nist-aal2 | pci-4.0 | hipaa-aal2",
  "  --min-length <n>       Override the profile minLength",
  "  --max-length <n>       Override the profile maxLength",
  "  --breach-check         Enable HaveIBeenPwned k-anonymity check (NETWORK)",
  "  --fail-closed          With --breach-check: HIBP outage → fail (default ok)",
  "  --email <addr>         Context for the deny-context-substrings check",
  "  --username <name>      Context for the deny-context-substrings check",
  "  --json                 Print machine-readable JSON",
].join("\n");

async function _runPassword(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs password").usage(PASSWORD_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs password " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(PASSWORD_USAGE);
  }
  if (sub !== "check") {
    cliHelpers.makeReporter(ctx, "blamejs password").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs password").usage(PASSWORD_USAGE);
  }
  var plaintext;
  if (args.flags.stdin) {
    try { plaintext = nodeFs.readFileSync(0, "utf8").replace(/\r?\n$/, ""); }
    catch (e) { return report.error("stdin read failed: " + ((e && e.message) || String(e))); }
  } else if (args.flags.plaintext && args.flags.plaintext !== true) {
    plaintext = String(args.flags.plaintext);
  } else {
    return report.error("--plaintext <s> or --stdin is required", 2);
  }
  var policyOpts = {};
  if (args.flags.profile && args.flags.profile !== true) policyOpts.profile = String(args.flags.profile);
  if (args.flags["min-length"] && args.flags["min-length"] !== true) {
    policyOpts.minLength = Number(args.flags["min-length"]);
  }
  if (args.flags["max-length"] && args.flags["max-length"] !== true) {
    policyOpts.maxLength = Number(args.flags["max-length"]);
  }
  if (args.flags["breach-check"]) {
    policyOpts.breachCheck = "haveibeenpwned";
    if (args.flags["fail-closed"]) policyOpts.failClosed = true;
  }
  var policy;
  try { policy = passwordModule.policy(policyOpts); }
  catch (e) { return report.error("bad policy: " + ((e && e.message) || String(e)), 2); }
  var context = {};
  if (args.flags.email && args.flags.email !== true)       context.email    = String(args.flags.email);
  if (args.flags.username && args.flags.username !== true) context.username = String(args.flags.username);
  var verdict;
  try { verdict = await policy.check(plaintext, context); }
  catch (e) { return report.error("check threw: " + ((e && e.message) || String(e))); }
  if (args.flags.json) {
    report.write(JSON.stringify(verdict));
    return verdict.ok ? 0 : 1;
  }
  if (verdict.ok) {
    report.write("ok");
    if (verdict.breachCheckSkipped) {
      report.write("  (HIBP skipped: " + verdict.breachCheckSkipReason + ")");
    } else if (typeof verdict.breachCheckCount === "number") {
      report.write("  (HIBP breach count: " + verdict.breachCheckCount + ")");
    }
    return 0;
  }
  report.write("REJECTED: " + verdict.code);
  report.write("  " + verdict.message);
  return 1;
}

// ---- Subcommand: erase -------------------------------------------
//
// Cryptographic-erasure of a single row. The right tool for one-off
// GDPR Art. 17 / right-to-erasure flows that don't fit the periodic
// retention sweep. Replaces every sealed column + derived hash with
// NULL, sets __erasedAt, and writes the row back. Cleartext is
// unrecoverable even with the vault key.

var ERASE_USAGE = [
  "Usage: blamejs erase --table <table> --row-id <id> [flags]",
  "",
  "Tombstones a single row's sealed columns + derived hashes. Used for",
  "one-off compliance erasure (GDPR Art. 17). The row stays in the table",
  "(referential integrity) but the cleartext is unrecoverable.",
  "",
  "Flags:",
  "  --data-dir <path>      Required",
  "  --table <name>         Required — the table containing the row",
  "  --row-id <id>          Required — the _id of the row to erase",
  "  --vault-mode <mode>    plaintext | wrapped (default wrapped)",
  "  --reason <text>        Reason recorded on the audit row (recommended)",
  "  --confirm              Required — confirms the erase is intentional",
].join("\n");

async function _runErase(args, ctx) {
  var report = cliHelpers.makeReporter(ctx, "blamejs erase");
  if (args.flags.help || args.flags.h) {
    return report.helpStdout(ERASE_USAGE);
  }
  var table = args.flags.table;
  var rowId = args.flags["row-id"];
  if (!table || table === true)  return report.error("--table <name> is required", 2);
  if (!rowId || rowId === true)  return report.error("--row-id <id> is required", 2);
  if (!args.flags.confirm) {
    return report.error("--confirm is required (this operation is irreversible)", 2);
  }
  var dataDirFlag = args.flags["data-dir"];
  if (!dataDirFlag || dataDirFlag === true) {
    return report.error("--data-dir <path> is required", 2);
  }
  var dataDir = _resolvePath(String(dataDirFlag), ctx.cwd);
  var vaultMode = args.flags["vault-mode"] || "wrapped";
  var reason = (args.flags.reason && args.flags.reason !== true) ? String(args.flags.reason) : null;
  var booted;
  try {
    booted = await cliHelpers.bootApp({ dataDir: dataDir, vaultMode: vaultMode, env: ctx.env });
  } catch (e) {
    return report.error("boot failed: " + ((e && e.message) || String(e)));
  }
  try {
    var b = booted.b;
    var safeTable = String(table).replace(/[^A-Za-z0-9_]/g, "");
    if (safeTable !== String(table) || safeTable.length === 0) {
      return report.error("--table must be a valid identifier (got " + JSON.stringify(table) + ")", 2);
    }
    var row;
    try {
      // Compose the lookup through b.sql so the identifier is quoted by
      // construction and the _id binds as a placeholder. quoteName: true
      // emits the local-sqlite `"table"` form (this runs against the
      // bootstrapped single-node b.db handle, no clusterStorage rewrite).
      var selBuilt = b.sql.select(safeTable, { quoteName: true })
        .where("_id", String(rowId)).toSql();
      var selStmt = b.db.prepare(selBuilt.sql);
      row = selStmt.get.apply(selStmt, selBuilt.params);
    } catch (e) {
      return report.error("row lookup failed: " + ((e && e.message) || String(e)));
    }
    if (!row) {
      return report.error("no row with _id=" + JSON.stringify(rowId) + " in table " + safeTable);
    }
    var schema = b.cryptoField.getSchema(safeTable);
    var sealedFields = schema && Array.isArray(schema.sealedFields) ? schema.sealedFields : [];
    var derivedHashes = schema && schema.derivedHashes ? Object.keys(schema.derivedHashes) : [];
    if (sealedFields.length === 0 && derivedHashes.length === 0) {
      return report.error("table " + safeTable + " has no sealed columns or derived hashes; " +
        "use a regular DELETE for non-sealed rows");
    }
    // NULL every sealed column + derived hash. Build the SET map for
    // b.sql.update — each column binds NULL as a placeholder, the
    // identifiers quote by construction, and the WHERE keeps the write
    // scoped to the single _id (b.sql refuses an unconditional update).
    var eraseSet = {};
    for (var si = 0; si < sealedFields.length; si++) eraseSet[sealedFields[si]] = null;
    for (var di = 0; di < derivedHashes.length; di++) eraseSet[derivedHashes[di]] = null;
    try {
      var updBuilt = b.sql.update(safeTable, { quoteName: true })
        .set(eraseSet).where("_id", String(rowId)).toSql();
      var upd = b.db.prepare(updBuilt.sql);
      upd.run.apply(upd, updBuilt.params);
    } catch (e) {
      return report.error("UPDATE failed: " + ((e && e.message) || String(e)));
    }
    try {
      b.audit.safeEmit({
        action:  "system.erase",
        outcome: "success",
        resource: { kind: "row.erase", id: safeTable + "/" + String(rowId) },
        reason:  reason,
        metadata: {
          table: safeTable, rowId: String(rowId),
          sealedFieldCount: sealedFields.length,
          derivedHashCount: derivedHashes.length,
        },
      });
    } catch (_e) { /* audit best-effort */ }
    report.write("erased: " + safeTable + "/" + String(rowId));
    report.write("  sealed columns nulled: " + sealedFields.join(", "));
    if (derivedHashes.length > 0) {
      report.write("  derived hashes nulled: " + derivedHashes.join(", "));
    }
    return report.ok();
  } finally {
    try { await booted.app.shutdown(); } catch (_e) { /* best-effort */ }
  }
}

// ---- Subcommand: retention ---------------------------------------
//
// Run / preview an ad-hoc retention rule from the CLI. Operators
// supply the rule shape on the command line — table + ageField +
// ttlMs + action — for one-off cleanups outside the scheduler-
// driven sweep wired in lib code.

var RETENTION_USAGE = [
  "Usage: blamejs retention <subcommand> [flags]",
  "",
  "Subcommands:",
  "  preview           Dry-run: report what WOULD be processed without acting",
  "  run               Run the rule once (acts on the rows it finds)",
  "",
  "Flags (all subcommands):",
  "  --data-dir <path>      Required",
  "  --vault-mode <mode>    plaintext | wrapped (default wrapped)",
  "  --table <name>         Required — table to sweep",
  "  --age-field <col>      Required — column holding the ms-epoch timestamp",
  "  --ttl-ms <ms>          Required — rows older than (now - ttlMs) are matched",
  "  --action <a>           erase (default) | delete | soft-delete",
  "  --soft-delete-field <col>",
  "                         For action=soft-delete — column to write the",
  "                         deletion timestamp into (required when action=soft-delete)",
  "  --legal-hold-field <col>",
  "                         Per-row legal-hold exemption column; rows where this",
  "                         is truthy are skipped",
  "  --batch-size <n>       Rows per batch (default 500)",
  "  --json                 Print machine-readable JSON summary",
].join("\n");

async function _runRetention(args, ctx) {
  if (args.pos.length === 0) {
    return cliHelpers.makeReporter(ctx, "blamejs retention").usage(RETENTION_USAGE);
  }
  var sub = args.pos[0];
  var report = cliHelpers.makeReporter(ctx, "blamejs retention " + sub);
  if (sub === "help" || args.flags.help || args.flags.h) {
    return report.helpStdout(RETENTION_USAGE);
  }
  if (["preview", "run"].indexOf(sub) === -1) {
    cliHelpers.makeReporter(ctx, "blamejs retention").error("unknown subcommand '" + sub + "'", 2);
    return cliHelpers.makeReporter(ctx, "blamejs retention").usage(RETENTION_USAGE);
  }
  var dataDirFlag = args.flags["data-dir"];
  if (!dataDirFlag || dataDirFlag === true) return report.error("--data-dir <path> is required", 2);
  var table   = args.flags.table;
  var ageField = args.flags["age-field"];
  var ttlMs   = args.flags["ttl-ms"];
  if (!table   || table === true)    return report.error("--table <name> is required", 2);
  if (!ageField || ageField === true) return report.error("--age-field <col> is required", 2);
  if (!ttlMs   || ttlMs === true)    return report.error("--ttl-ms <ms> is required", 2);
  var ttlMsNum = Number(ttlMs);
  if (!isFinite(ttlMsNum) || ttlMsNum <= 0) {
    return report.error("--ttl-ms must be a positive finite number", 2);
  }
  var action = args.flags.action ? String(args.flags.action) : "erase";
  if (["erase", "delete", "soft-delete"].indexOf(action) === -1) {
    return report.error("--action must be erase / delete / soft-delete", 2);
  }
  if (action === "soft-delete" &&
      (!args.flags["soft-delete-field"] || args.flags["soft-delete-field"] === true)) {
    return report.error("--soft-delete-field <col> required when --action=soft-delete", 2);
  }
  var batchSize = args.flags["batch-size"] && args.flags["batch-size"] !== true
    ? Number(args.flags["batch-size"]) : 500;
  var dataDir = _resolvePath(String(dataDirFlag), ctx.cwd);
  var vaultMode = args.flags["vault-mode"] || "wrapped";
  var booted;
  try {
    booted = await cliHelpers.bootApp({ dataDir: dataDir, vaultMode: vaultMode, env: ctx.env });
  } catch (e) {
    return report.error("boot failed: " + ((e && e.message) || String(e)));
  }
  try {
    var rules = booted.b.retention.create({ db: booted.b.db, audit: booted.b.audit });
    var ruleSpec = {
      name:      "cli-" + String(table) + "-" + Date.now(),
      table:     String(table),
      ageField:  String(ageField),
      ttlMs:     ttlMsNum,
      action:    action,
      batchSize: batchSize,
    };
    if (args.flags["soft-delete-field"] && args.flags["soft-delete-field"] !== true) {
      ruleSpec.softDeleteField = String(args.flags["soft-delete-field"]);
    }
    if (args.flags["legal-hold-field"] && args.flags["legal-hold-field"] !== true) {
      ruleSpec.legalHoldField = String(args.flags["legal-hold-field"]);
    }
    rules.declare(ruleSpec);
    var summary = await rules.run(ruleSpec.name, { dryRun: sub === "preview" });
    if (args.flags.json) {
      report.write(JSON.stringify(summary, null, 2));
    } else {
      report.write((sub === "preview" ? "DRY-RUN " : "") + "rule:    " + ruleSpec.name);
      report.write("table:    " + ruleSpec.table);
      report.write("scanned:  " + summary.scanned);
      report.write("processed:" + summary.processed);
      report.write("skipped:  " + summary.skipped);
      report.write("legalHoldsHonored: " + summary.legalHoldsHonored);
      if (summary.errors && summary.errors.length > 0) {
        report.write("errors:   " + summary.errors.length);
        for (var ei = 0; ei < Math.min(summary.errors.length, 5); ei++) {
          report.write("  - " + (summary.errors[ei].rowId || "?") + ": " + summary.errors[ei].reason);
        }
      }
      report.write("durationMs: " + summary.durationMs);
    }
    return summary.errors && summary.errors.length > 0 ? 1 : 0;
  } catch (e) {
    return report.error((e && e.message) || String(e));
  } finally {
    try { await booted.app.shutdown(); } catch (_e) { /* best-effort */ }
  }
}

var TOP_USAGE = [
  "Usage: blamejs <command> [args]",
  "",
  "Commands:",
  "  migrate           Manage database migrations (up / down / status)",
  "  seed              Apply seed-data fixtures by env (run / status)",
  "  dev               Run an app with file-watch + auto-restart",
  "  api-snapshot      Capture / compare the public API surface (CI gate)",
  "  api-key           Issue / revoke / list / rotate / verify API keys for a namespace",
  "  audit             Operator tooling on top of the audit chain (archive / export / verify / purge)",
  "  backup            Inspect / verify / extract a backup bundle from disk",
  "  restore           Live in-place restore from a bundle (list / inspect / apply / rollback / list-rollbacks)",
  "  mtls              Inspect or generate the in-box mTLS CA + leaf certs (status / show-cert / init / issue / issue-p12)",
  "  vault             Seal / unseal / rotate the on-disk vault keypair (plaintext ↔ wrapped)",
  "  security          Run b.security.assertProduction against the live framework",
  "  config-drift      Inspect / verify the b.configDrift signed sidecar",
  "  file-type         Magic-byte content classification (b.fileType.detect)",
  "  password          Test b.auth.password.policy against a candidate plaintext",
  "  erase             Cryptographically erase a single row's sealed columns (GDPR Art. 17)",
  "  retention         Run / preview an ad-hoc b.retention rule",
  "  version           Print framework version",
  "  help [<command>]  Show this message or details for a command",
].join("\n");

function _printTopHelp(ctx) { _writeLine(ctx.stdout, TOP_USAGE); }

// ---- Dispatch ----

async function main(argv, opts) {
  opts = opts || {};
  var ctx = {
    stdout: opts.stdout || process.stdout,
    stderr: opts.stderr || process.stderr,
    env:    opts.env    || process.env,
    cwd:    opts.cwd    || process.cwd(),
  };
  if (!Array.isArray(argv)) argv = [];
  var args = _parseArgs(argv);

  // Top-level flags handled before subcommand dispatch
  if (args.flags.version || args.flags.v) {
    _writeLine(ctx.stdout, C.version);
    return 0;
  }

  var cmd = args.pos[0];

  // --help routing:
  //   `blamejs --help`            → top-level help
  //   `blamejs <cmd> --help`      → that command's USAGE (via the
  //                                 existing `help <cmd>` dispatch
  //                                 block below). Synthesizing the
  //                                 positional form keeps every
  //                                 subcommand's per-command usage
  //                                 reachable via `--help` without
  //                                 each handler having to special-case
  //                                 the flag-only-no-subcommand nodePath.
  if (cmd === undefined) { _printTopHelp(ctx); return 0; }
  if (args.flags.help || args.flags.h) {
    args = _parseArgs(["help", cmd]);
    cmd  = "help";
  }
  if (cmd === "help") {
    var subTopic = args.pos[1];
    if (subTopic === "migrate")      { _writeLine(ctx.stdout, MIGRATE_USAGE);      return 0; }
    if (subTopic === "seed")         { _writeLine(ctx.stdout, SEED_USAGE);         return 0; }
    if (subTopic === "dev")          { _writeLine(ctx.stdout, DEV_USAGE);          return 0; }
    if (subTopic === "api-snapshot") { _writeLine(ctx.stdout, API_SNAPSHOT_USAGE); return 0; }
    if (subTopic === "api-key")      { _writeLine(ctx.stdout, API_KEY_USAGE);      return 0; }
    if (subTopic === "audit")        { _writeLine(ctx.stdout, AUDIT_USAGE);        return 0; }
    if (subTopic === "backup")       { _writeLine(ctx.stdout, BACKUP_USAGE);       return 0; }
    if (subTopic === "restore")      { _writeLine(ctx.stdout, RESTORE_USAGE);      return 0; }
    if (subTopic === "mtls")         { _writeLine(ctx.stdout, MTLS_USAGE);         return 0; }
    if (subTopic === "vault")        { _writeLine(ctx.stdout, VAULT_USAGE);        return 0; }
    if (subTopic === "security")     { _writeLine(ctx.stdout, SECURITY_USAGE);     return 0; }
    if (subTopic === "config-drift") { _writeLine(ctx.stdout, CONFIG_DRIFT_USAGE); return 0; }
    if (subTopic === "file-type")    { _writeLine(ctx.stdout, FILE_TYPE_USAGE);    return 0; }
    if (subTopic === "password")     { _writeLine(ctx.stdout, PASSWORD_USAGE);     return 0; }
    if (subTopic === "erase")        { _writeLine(ctx.stdout, ERASE_USAGE);        return 0; }
    if (subTopic === "retention")    { _writeLine(ctx.stdout, RETENTION_USAGE);    return 0; }
    _printTopHelp(ctx);
    return 0;
  }
  if (cmd === "version") { _writeLine(ctx.stdout, C.version); return 0; }

  var rest = { pos: args.pos.slice(1), flags: args.flags };
  if (cmd === "migrate")      return await _runMigrate(rest, ctx);
  if (cmd === "seed")         return await _runSeed(rest, ctx);
  if (cmd === "dev")          return await _runDev(rest, ctx);
  if (cmd === "api-snapshot") return _runApiSnapshot(rest, ctx);
  if (cmd === "api-key")      return await _runApiKey(rest, ctx);
  if (cmd === "audit")        return await _runAudit(rest, ctx);
  if (cmd === "backup")       return await _runBackup(rest, ctx);
  if (cmd === "restore")      return await _runRestore(rest, ctx);
  if (cmd === "mtls")         return await _runMtls(rest, ctx);
  if (cmd === "vault")        return await _runVault(rest, ctx);
  if (cmd === "security")     return await _runSecurity(rest, ctx);
  if (cmd === "config-drift") return await _runConfigDrift(rest, ctx);
  if (cmd === "file-type")    return _runFileType(rest, ctx);
  if (cmd === "password")     return await _runPassword(rest, ctx);
  if (cmd === "erase")        return await _runErase(rest, ctx);
  if (cmd === "retention")    return await _runRetention(rest, ctx);

  _writeLine(ctx.stderr, "blamejs: unknown command '" + cmd + "'");
  _printTopHelp(ctx);
  return 2;
}

module.exports = {
  main:        main,
  // Internal helpers exposed so tests can drive the parser without
  // running the full dispatch.
  _parseArgs:  _parseArgs,
  TOP_USAGE:           TOP_USAGE,
  MIGRATE_USAGE:       MIGRATE_USAGE,
  DEV_USAGE:           DEV_USAGE,
  API_SNAPSHOT_USAGE:  API_SNAPSHOT_USAGE,
  API_KEY_USAGE:       API_KEY_USAGE,
  AUDIT_USAGE:         AUDIT_USAGE,
  BACKUP_USAGE:        BACKUP_USAGE,
  RESTORE_USAGE:       RESTORE_USAGE,
  MTLS_USAGE:          MTLS_USAGE,
  VAULT_USAGE:         VAULT_USAGE,
};
