#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * @module     stash.cli
 * @nav        Tools
 * @title      CLI
 * @order      60
 * @slug       cli
 *
 * @intro
 *   The operational CLI: inspect and maintain a disk-backed stash from the shell
 *   without writing a Node program. It ships as the `stashjs` command
 *   (`npx @blamejs/stash <subcommand>`) and composes ONLY the query and
 *   maintenance verbs: `verify`, `stats`, `prune`, `list`, `tombstones`, `has`.
 *   It never moves bytes, hands out no capability, and streams no blob, so
 *   `push`, `apply`, `pop`, `store`, `drop`, and `clear` belong to the embedding
 *   application rather than a maintenance tool.
 *
 *   The root comes from `--root <dir>`, else `STASH_ROOT`, else `./.stash`, and it
 *   must already exist as a disk backend layout: a missing root is refused, never
 *   conjured from a typo. Add `--json` to any subcommand for a machine-readable
 *   document instead of the human table.
 *
 *   Single-writer-per-root is the store's operating constraint (SPEC.md 6): every
 *   subcommand except `verify` runs the crash-recovery scan first and can reclaim a
 *   stale claim, so point the CLI at a stash whose owning process is stopped, or at
 *   a cold-standby replica, never at a root a live app is serving.
 *
 *   Errors fail closed with stable exit codes and never echo a ref, a meta value,
 *   or a filesystem path. Run under `node --permission` with read/write scoped to
 *   the root (plus read on the install dir) exactly as the library requires.
 *
 * @card
 *   Inspect and maintain a disk stash from the shell (verify, stats, prune, list,
 *   tombstones, has) without writing Node. Never moves bytes.
 */

import { realpathSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { DiskBackend, SUBDIRS } from "./backends/disk.js";
import { StashError } from "./errors.js";
import { Stash, version } from "./index.js";
import { isValid } from "./ref.js";

// One exit code per verdict class so a cron/fsck caller can branch; frozen alongside the
// error catalog (SPEC.md 10).
export const EXIT = Object.freeze({
  OK: 0, // success, or a clean verify
  DAMAGE: 1, // verify found findings (the fsck convention -- alert on non-zero)
  USAGE: 2, // bad invocation: unknown subcommand/flag, missing argument
  BAD_REF: 3, // a malformed ref was refused (EBADREF) before any backend access
  INTEGRITY: 4, // stored bytes disagreed with their manifest (EINTEGRITY)
  FAULT: 5, // an I/O or access fault, or any other typed error
});

// Keys on the frozen StashError code (SPEC.md 10), never the message, so it cannot drift.
function exitForError(err) {
  if (err instanceof StashError) {
    if (err.code === "EBADREF") return EXIT.BAD_REF;
    if (err.code === "EINTEGRITY") return EXIT.INTEGRITY;
  }
  return EXIT.FAULT;
}

// A usage fault (exit 2). Static messages only: a ref mistyped as a subcommand must not
// echo back as a pseudo-capability.
class UsageError extends Error {}

const HELP = `stashjs -- inspect and maintain a disk-backed @blamejs/stash from the shell.

Usage: stashjs <command> [--root <dir>] [--json] [command flags]

Commands:
  verify [--repair]        Audit the store for damage; --repair removes condemned
                           blob/sidecar pairs, orphans, and corrupt graves.
  stats                    Print entry count, stored bytes, and claimed count.
  prune                    Destroy already-expired entries and reap old graves.
  list [--include-expired] List entries (metadata only, never contents).
  tombstones               List the graves left by destroyed entries.
  has <ref>                Print whether a ref is present (true/false).

Root resolution: --root <dir>, else $STASH_ROOT, else ./.stash. The root must
already exist as a disk backend layout; a missing root is refused, not created.

Add --json to any command for a machine-readable document. --version prints the
version. Point this only at a quiesced stash or a cold-standby replica: every
command except verify runs the crash-recovery scan and can reclaim a stale claim.`;

function resolveRoot(flags, env) {
  if (flags.root !== undefined) return flags.root;
  if (env.STASH_ROOT) return env.STASH_ROOT;
  return "./.stash";
}

// Refuse a missing root rather than letting DiskBackend #init conjure an empty store
// from a typo, which would report "0 entries" and mask the mistake.
function assertStashLayout(root) {
  // Require EVERY directory #init creates (SUBDIRS, imported so this cannot drift),
  // since #init would otherwise re-create a missing one on first use. ENOENT/ENOTDIR is
  // "no stash here"; an access or I/O fault is a REAL fault, surfaced and never masked.
  for (const sub of SUBDIRS) {
    let st;
    try {
      st = statSync(join(root, sub));
    } catch (err) {
      if (err.code === "ENOENT" || err.code === "ENOTDIR") {
        throw new UsageError("stash root not found (expected an existing disk backend layout)");
      }
      throw err; // EACCES / EIO / ... -- a real access fault, not a usage error
    }
    if (!st.isDirectory()) {
      throw new UsageError("stash root is not a disk backend layout");
    }
  }
}

const COMMON = { root: { type: "string" }, json: { type: "boolean", default: false } };
const COMMANDS = {
  verify: {
    options: { ...COMMON, repair: { type: "boolean", default: false } },
    positionals: 0,
    run: cmdVerify,
  },
  stats: { options: { ...COMMON }, positionals: 0, run: cmdStats },
  prune: { options: { ...COMMON }, positionals: 0, run: cmdPrune },
  list: {
    options: { ...COMMON, "include-expired": { type: "boolean", default: false } },
    positionals: 0,
    run: cmdList,
  },
  tombstones: { options: { ...COMMON }, positionals: 0, run: cmdTombstones },
  has: { options: { ...COMMON }, positionals: 1, refPositional: true, run: cmdHas },
};

// Exported so a test pins that --help documents every subcommand.
export const COMMAND_NAMES = Object.freeze(Object.keys(COMMANDS));

// One-shot: no sweep timer, and the restore-on-pop-failure default, because an
// inspection tool must never silently BURN an abandoned claim.
function openStash(root) {
  assertStashLayout(root);
  return new Stash({ backend: new DiskBackend({ root }), sweepInterval: null });
}

function render(io, json, human, machine) {
  io.out.write((json ? JSON.stringify(machine) : human) + "\n");
}

function pad(value, width) {
  const s = String(value);
  return s.length >= width ? s : s + " ".repeat(width - s.length);
}

function whenText(ms) {
  return ms === null ? "never" : new Date(ms).toISOString();
}

async function cmdVerify(stash, flags, _pos, io) {
  const report = await stash.verify({ repair: flags.repair });
  if (flags.json) {
    io.out.write(JSON.stringify(report) + "\n");
  } else {
    const lines = [
      `scanned ${report.scanned}, findings ${report.findings.length}, repaired ${report.repaired.length}`,
    ];
    for (const f of report.findings)
      lines.push(`  ${pad(f.kind, 18)} ${f.id === null ? "(unnamed)" : f.id}`);
    io.out.write(lines.join("\n") + "\n");
  }
  // DAMAGE only if damage REMAINS: a dry run leaves every finding unresolved, while
  // --repair clears what it condemned, so what is left is what repair would not fix.
  const unresolved = report.findings.filter(
    (f) => !report.repaired.some((r) => r.kind === f.kind && r.id === f.id),
  );
  return unresolved.length > 0 ? EXIT.DAMAGE : EXIT.OK;
}

async function cmdStats(stash, flags, _pos, io) {
  const stats = await stash.stats();
  render(
    io,
    flags.json,
    `entries ${stats.entries}, bytes ${stats.bytes}, claimed ${stats.claimed}`,
    stats,
  );
  return EXIT.OK;
}

async function cmdPrune(stash, flags, _pos, io) {
  const pruned = await stash.prune();
  render(io, flags.json, `pruned ${pruned}`, { pruned });
  return EXIT.OK;
}

async function cmdList(stash, flags, _pos, io) {
  const entries = await stash.list({ includeExpired: flags["include-expired"] });
  if (flags.json) {
    io.out.write(JSON.stringify(entries) + "\n");
  } else {
    // The human view omits `meta`, a needless disclosure in a casual table.
    const lines = [
      `${pad("ref", 47)} ${pad("size", 10)} ${pad("created", 26)} ${pad("expires", 26)} reads`,
    ];
    for (const e of entries) {
      lines.push(
        `${pad(e.id, 47)} ${pad(e.size, 10)} ${pad(whenText(e.createdAt), 26)} ${pad(whenText(e.expiresAt), 26)} ${e.readsLeft === null ? "-" : e.readsLeft}`,
      );
    }
    io.out.write(lines.join("\n") + "\n");
  }
  return EXIT.OK;
}

async function cmdTombstones(stash, flags, _pos, io) {
  const graves = await stash.tombstones();
  if (flags.json) {
    io.out.write(JSON.stringify(graves) + "\n");
  } else {
    const lines = [`${pad("ref", 47)} ${pad("destroyed", 26)} cause`];
    for (const g of graves)
      lines.push(`${pad(g.id, 47)} ${pad(whenText(g.destroyedAt), 26)} ${g.cause}`);
    io.out.write(lines.join("\n") + "\n");
  }
  return EXIT.OK;
}

async function cmdHas(stash, flags, pos, io) {
  // stash.has validates the ref at the whitelist BEFORE any backend access, so a
  // malformed ref throws InvalidRef (EBADREF), caught below as BAD_REF. Present and
  // absent both exit OK; the boolean is the answer, a non-zero exit is a real error.
  const present = await stash.has(pos[0]);
  render(io, flags.json, present ? "true" : "false", { present });
  return EXIT.OK;
}

// `io` = { out, err, env } so the surface is testable in-process. Never calls
// process.exit; the entry guard below does, from the returned code.
export async function main(argv, io) {
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) {
    io.out.write(HELP + "\n");
    return EXIT.OK;
  }
  if (argv.includes("--version") || argv.includes("-V")) {
    io.out.write(version + "\n");
    return EXIT.OK;
  }
  // COMMANDS is indexed by an UNTRUSTED argv token, so membership is Object.hasOwn: a
  // token naming an inherited Object.prototype member ("constructor", "__proto__") would
  // resolve and slip past the `spec === undefined` guard as a phantom command (CWE-1321).
  const name = argv[0];
  const spec = Object.hasOwn(COMMANDS, name) ? COMMANDS[name] : undefined;
  if (spec === undefined) {
    io.err.write("stashjs: unknown command (run stashjs --help)\n");
    return EXIT.USAGE;
  }
  let parsed;
  try {
    parsed = parseArgs({
      args: argv.slice(1),
      options: spec.options,
      allowPositionals: true,
      strict: true,
    });
  } catch {
    // parseArgs's message can quote operator input, so it is swallowed for a static line.
    io.err.write("stashjs: invalid options (run stashjs --help)\n");
    return EXIT.USAGE;
  }
  if (parsed.positionals.length !== spec.positionals) {
    io.err.write("stashjs: wrong number of arguments (run stashjs --help)\n");
    return EXIT.USAGE;
  }
  // Ref validation precedes any storage access, so a malformed ref costs zero I/O.
  if (spec.refPositional && !isValid(parsed.positionals[0])) {
    io.err.write("stashjs: EBADREF\n");
    return EXIT.BAD_REF;
  }
  let stash;
  try {
    stash = openStash(resolveRoot(parsed.values, io.env));
    return await spec.run(stash, parsed.values, parsed.positionals, io);
  } catch (err) {
    if (err instanceof UsageError) {
      io.err.write("stashjs: " + err.message + "\n");
      return EXIT.USAGE;
    }
    // Fail loud, capability-free: the frozen code, never the ref/meta/path.
    io.err.write(
      "stashjs: " + (err instanceof StashError ? err.code : "a filesystem or access fault") + "\n",
    );
    return exitForError(err);
  } finally {
    if (stash) await stash.close();
  }
}

// Run only when invoked as the bin, never on import. Compare real paths so a relative
// argv, a symlinked bin shim, and Windows separators all resolve alike.
function invokedAsEntry() {
  if (process.argv[1] === undefined) return false;
  let entry = null;
  let self = null;
  try {
    entry = realpathSync(process.argv[1]);
    self = realpathSync(fileURLToPath(import.meta.url));
  } catch {
    // An unresolvable path is not this entry: fall through with both left null.
    entry = null;
  }
  return entry !== null && entry === self;
}

if (invokedAsEntry()) {
  main(process.argv.slice(2), { out: process.stdout, err: process.stderr, env: process.env })
    .then((code) => process.exit(code))
    .catch(() => process.exit(EXIT.FAULT));
}
