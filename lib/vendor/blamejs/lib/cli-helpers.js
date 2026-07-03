// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.cliHelpers
 * @nav    Production
 * @title  CLI Helpers
 *
 * @intro
 *   Shared shape for blamejs CLI subcommands AND for operators
 *   writing their own one-shot CLI scripts on top of the framework.
 *   Three patterns recur across every CLI command (`migrate`, `seed`,
 *   `audit`, `vault`, `backup`, `api-key`): bootstrap a headless
 *   `b.createApp` instance from `--data-dir` and shut it down cleanly;
 *   report success / error / usage with a consistent
 *   `blamejs <verb> <sub>: <message>` prefix on stderr plus canonical
 *   exit codes (0 ok, 1 runtime failure, 2 arg error); resolve a
 *   passphrase from a `--<flag>` or env var into the Buffer shape
 *   the underlying crypto primitives accept.
 *
 *   The reporter writes through whichever stream `ctx.stdout` /
 *   `ctx.stderr` point at — `process.stdout` / `process.stderr` in
 *   production, captured stream stubs in tests — so the same handler
 *   is testable without spawning a child process.
 *
 * @card
 *   Shared shape for blamejs CLI subcommands AND for operators writing their own one-shot CLI scripts on top of the framework.
 */

var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");

// lazyRequire the framework root so cli-helpers stays loadable in
// contexts that aren't the framework root (tests, operator-side
// scripts importing only cli-helpers). The first bootApp() call
// resolves the framework module; subsequent calls reuse the cached
// load.
var blamejs = lazyRequire(function () { return require("../"); });

// ---- Streams + exit-code-shaped reporting --------------------------------

function _writeLine(stream, line) {
  if (!stream || typeof stream.write !== "function") return;
  if (line == null) return;
  stream.write(String(line) + "\n");
}

/**
 * @primitive b.cliHelpers.makeReporter
 * @signature b.cliHelpers.makeReporter(ctx, prefix)
 * @since     0.8.0
 * @status    stable
 * @related   b.cliHelpers.resolvePassphrase, b.cliHelpers.bootApp
 *
 * Build a reporter bound to a CLI context (`ctx.stdout` /
 * `ctx.stderr`) and a verb prefix. Every stderr message produced by
 * `.error` / `.usage` gets the prefix. Methods return canonical
 * Unix exit codes — `0` for `ok` / `helpStdout`, `1` for `error`
 * (override via second arg), `2` for `usage` (argument-error
 * convention).
 *
 * @example
 *   var ctx = { stdout: process.stdout, stderr: process.stderr };
 *   var report = b.cliHelpers.makeReporter(ctx, "blamejs vault seal");
 *   var ok   = report.ok("sealed: /data/vault");        // → 0
 *   var fail = report.error("decrypt failed");          // → 1
 *   var arg  = report.error("missing --data-dir", 2);   // → 2
 *   var help = report.usage("Usage: blamejs vault ..."); // → 2
 */
function makeReporter(ctx, prefix) {
  if (!ctx || typeof ctx !== "object") {
    throw new Error("cliHelpers.makeReporter: ctx is required");
  }
  if (typeof prefix !== "string" || prefix.length === 0) {
    throw new Error("cliHelpers.makeReporter: prefix is required (non-empty string)");
  }
  var stdout = ctx.stdout || (typeof process !== "undefined" ? process.stdout : null);
  var stderr = ctx.stderr || (typeof process !== "undefined" ? process.stderr : null);
  return {
    ok: function (message) {
      if (message != null) _writeLine(stdout, message);
      return 0;
    },
    error: function (message, exitCode) {
      _writeLine(stderr, prefix + ": " + message);
      return typeof exitCode === "number" ? exitCode : 1;
    },
    usage: function (usageText) {
      _writeLine(stderr, usageText);
      return 2;
    },
    helpStdout: function (usageText) {
      _writeLine(stdout, usageText);
      return 0;
    },
    // Direct access for handlers that have multi-line output.
    write:    function (line) { _writeLine(stdout, line); },
    writeErr: function (line) { _writeLine(stderr, line); },
  };
}

// ---- Passphrase resolution -----------------------------------------------

/**
 * @primitive b.cliHelpers.resolvePassphrase
 * @signature b.cliHelpers.resolvePassphrase(args, ctx, opts)
 * @since     0.8.0
 * @status    stable
 * @related   b.cliHelpers.makeReporter, b.cliHelpers.bootApp
 *
 * Resolve a passphrase from a CLI flag (preferred) or an env var
 * (fallback) into a UTF-8 Buffer — the shape vault / crypto
 * primitives accept. Returns `null` when neither source produced a
 * non-empty string; the caller decides whether absence is a hard
 * error (vault seal) or a soft default (plaintext-mode dev data dir).
 *
 * @opts
 *   flag:    string  (CLI flag name, e.g. "passphrase" reads args.flags.passphrase),
 *   envVar:  string  (env var fallback, e.g. "BLAMEJS_VAULT_PASSPHRASE"),
 *
 * @example
 *   var args = { flags: { passphrase: "hunter2" } };
 *   var ctx  = { env: { BLAMEJS_VAULT_PASSPHRASE: "envval" } };
 *   var pp = b.cliHelpers.resolvePassphrase(args, ctx, {
 *     flag:   "passphrase",
 *     envVar: "BLAMEJS_VAULT_PASSPHRASE",
 *   });
 *   pp.toString("utf8");     // → "hunter2"  (flag wins over env)
 *
 *   var none = b.cliHelpers.resolvePassphrase({ flags: {} }, { env: {} }, {
 *     flag: "passphrase", envVar: "BLAMEJS_VAULT_PASSPHRASE",
 *   });
 *   none;                    // → null
 */
function resolvePassphrase(args, ctx, opts) {
  opts = opts || {};
  validateOpts(opts, ["flag", "envVar"], "cliHelpers.resolvePassphrase");
  if (typeof opts.flag !== "string" || opts.flag.length === 0) {
    throw new Error("cliHelpers.resolvePassphrase: opts.flag is required");
  }
  var raw = null;
  if (args && args.flags && typeof args.flags[opts.flag] === "string" &&
      args.flags[opts.flag].length > 0) {
    raw = args.flags[opts.flag];
  } else if (opts.envVar && ctx && ctx.env &&
             typeof ctx.env[opts.envVar] === "string" &&
             ctx.env[opts.envVar].length > 0) {
    raw = ctx.env[opts.envVar];
  }
  if (raw == null) return null;
  return Buffer.from(raw, "utf8");
}

// ---- Headless app bootstrap ----------------------------------------------

/**
 * @primitive b.cliHelpers.bootApp
 * @signature b.cliHelpers.bootApp(opts)
 * @since     0.8.0
 * @status    stable
 * @related   b.cliHelpers.makeReporter, b.cliHelpers.resolvePassphrase
 *
 * Boot a headless `b.createApp` instance from a data dir so a CLI
 * script (framework subcommand or operator-written tool) can operate
 * against the same vault + DB + audit chain the live app uses, with
 * no HTTP listener attached. Returns `{ b, app }` where `b` is the
 * framework module and `app` is the headless instance — caller MUST
 * `await booted.app.shutdown()` in a `finally` so SQLite file handles
 * and the cluster lease release.
 *
 * The default DB at-rest mode is `plain` because CLI runs are
 * short-lived ops that never serve requests; encrypted-at-rest needs
 * a tmpfs handle that wouldn't survive CLI exit anyway. Operators
 * running against a production data dir whose DB is encrypted-at-rest
 * pass `dbAtRest: "encrypted"` and ensure `BLAMEJS_TMPDIR` is set.
 *
 * @opts
 *   dataDir:    string   (filesystem path to the data dir; required),
 *   vaultMode:  "wrapped" | "plaintext"   (default "wrapped" — wrapped
 *               reads BLAMEJS_VAULT_PASSPHRASE from `opts.env`),
 *   dbAtRest:   "plain" | "encrypted"     (default "plain"),
 *   env:        object    (env-var bag; default process.env),
 *
 * @example
 *   async function run() {
 *     var booted;
 *     try {
 *       booted = await b.cliHelpers.bootApp({
 *         dataDir:   "./data",
 *         vaultMode: "plaintext",
 *         env:       process.env,
 *       });
 *       var rows = await booted.app.db.all("SELECT count(*) AS n FROM _blamejs_audit_log");
 *       return rows[0].n;
 *     } finally {
 *       if (booted) await booted.app.shutdown();
 *     }
 *   }
 */
async function bootApp(opts) {
  opts = opts || {};
  validateOpts(opts, ["dataDir", "vaultMode", "dbAtRest", "env"], "cliHelpers.bootApp");
  if (typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new Error("cliHelpers.bootApp: opts.dataDir is required");
  }
  var vaultMode = opts.vaultMode || "wrapped";
  if (vaultMode !== "wrapped" && vaultMode !== "plaintext") {
    throw new Error("cliHelpers.bootApp: opts.vaultMode must be 'wrapped' or 'plaintext'");
  }
  var env = opts.env || (typeof process !== "undefined" ? process.env : {});

  var vaultPassphrase = null;
  if (vaultMode === "wrapped") {
    var raw = env && env.BLAMEJS_VAULT_PASSPHRASE;
    if (typeof raw !== "string" || raw.length === 0) {
      throw new Error("cliHelpers.bootApp: BLAMEJS_VAULT_PASSPHRASE is required " +
        "for vault mode 'wrapped' (pass vaultMode: 'plaintext' for a dev data dir)");
    }
    vaultPassphrase = Buffer.from(raw, "utf8");
  }

  var b = blamejs();
  var app = await b.createApp({
    dataDir: opts.dataDir,
    routes:  function () {},
    vault:   { mode: vaultMode, passphrase: vaultPassphrase },
    db:      {
      atRest:       opts.dbAtRest || "plain",
      auditSigning: { mode: "plaintext" },
    },
  });
  return { b: b, app: app };
}

module.exports = {
  makeReporter:       makeReporter,
  resolvePassphrase:  resolvePassphrase,
  bootApp:            bootApp,
};
