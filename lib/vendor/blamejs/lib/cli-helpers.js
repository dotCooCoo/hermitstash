"use strict";
/**
 * cli-helpers — shared shape for blamejs CLI subcommands AND for
 * operators writing their own one-shot CLI scripts on top of the
 * framework.
 *
 * Three patterns recur across every CLI command (`migrate`, `seed`,
 * `audit`, `vault`, `backup`, `api-key`):
 *
 *   1. Bootstrap a headless `b.createApp` instance from `--data-dir`,
 *      operate against vault + DB + audit chain, shut down cleanly.
 *   2. Report success / error / usage with a consistent
 *      `blamejs <verb> <sub>: <message>` prefix on stderr + canonical
 *      exit codes (0 ok, 1 runtime failure, 2 arg error).
 *   3. Resolve a passphrase from `--<flag>` or an env var, encode to
 *      the Buffer the underlying crypto primitive needs.
 *
 *   var cli = b.cliHelpers;
 *
 *   var report = cli.makeReporter(ctx, "blamejs my-tool issue");
 *   if (!args.flags["data-dir"]) return report.usage(MY_USAGE);
 *
 *   var pp = cli.resolvePassphrase(args, ctx, {
 *     flag:   "passphrase",
 *     envVar: "MY_TOOL_PASSPHRASE",
 *   });
 *   if (!pp) return report.error("--passphrase or MY_TOOL_PASSPHRASE is required", 2);
 *
 *   var booted;
 *   try {
 *     booted = await cli.bootApp({
 *       dataDir:   args.flags["data-dir"],
 *       vaultMode: "wrapped",
 *       env:       ctx.env,
 *     });
 *     // do the op against booted.b.X / booted.app.db / etc.
 *     return report.ok("done");
 *   } catch (e) {
 *     return report.error(e.message);
 *   } finally {
 *     if (booted) await booted.app.shutdown();
 *   }
 *
 * The reporter writes through whichever stream `ctx.stdout` / `ctx.stderr`
 * point at — `process.stdout` / `process.stderr` in production, captured
 * stream stubs in tests — so the same handler is testable without
 * spawning a child process.
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
 * Make a reporter bound to a CLI context + a verb prefix. Every
 * stderr message produced by .error / .usage gets the prefix.
 *
 *   var report = cliHelpers.makeReporter(ctx, "blamejs vault seal");
 *   return report.ok("sealed: " + path);   // stdout, returns 0
 *   return report.error("decrypt failed"); // stderr "blamejs vault seal: decrypt failed", returns 1
 *   return report.error("missing arg", 2); // returns 2 (arg error vs runtime)
 *   return report.usage(VAULT_USAGE);      // stderr USAGE, returns 2
 *   return report.helpStdout(VAULT_USAGE); // stdout USAGE, returns 0 (for `help <verb>`)
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
 * Resolve a passphrase from a flag or env var into a UTF-8 Buffer
 * (the shape the underlying crypto primitives accept).
 *
 *   cli.resolvePassphrase(args, ctx, { flag: "passphrase", envVar: "BLAMEJS_VAULT_PASSPHRASE" })
 *     → Buffer | null
 *
 * Returns `null` when neither source produced a non-empty string. The
 * caller decides whether absence is a hard error (vault seal) or a
 * soft default (operator chose plaintext-mode).
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
 * Boot a serverless `b.createApp` instance from a data dir so a CLI
 * script (the framework's own subcommands or operator-written tools)
 * can operate against the same vault + DB + audit chain the live app
 * uses, without standing up an HTTP listener.
 *
 *   var booted = await cli.bootApp({
 *     dataDir:   "./data",
 *     vaultMode: "wrapped",   // or "plaintext"; default "wrapped"
 *     env:       process.env, // BLAMEJS_VAULT_PASSPHRASE read from here
 *   });
 *   // booted.b — the framework module
 *   // booted.app — the headless app instance (call .shutdown() to clean up)
 *
 * Caller MUST call `await booted.app.shutdown()` in a `finally` so the
 * SQLite file handles + cluster lease release. The default DB at-rest
 * mode is `plain` because CLI runs are short-lived ops that never
 * serve requests; the encrypted-at-rest mode needs a tmpfs handle that
 * wouldn't survive the CLI exit anyway. Operators running against a
 * production data dir whose DB is encrypted-at-rest set
 * `dbAtRest: "encrypted"` and ensure `BLAMEJS_TMPDIR` is set.
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
