// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Exercises lib/cli.js branches not driven by the per-command
// cli-*.test.js files or test/00-primitives.js:
//   - the `seed` subcommand (arg validation + a local-sqlite status run)
//   - `dev --grace-ms` numeric validation
//   - `api-snapshot` operator-supplied `--module` (capture + compare
//     failure paths)
//   - top-level `--help` / `-h` routing + unknown help topic fall-through
// Everything drives the public b.cli.main(argv, ctx) surface with a
// captured-output ctx; nothing here needs a live network/db backend
// (the sqlite handle is a local temp file, same shape the existing
// cli-audit-verify-chain / migrate tests use).
// It also drives the seed RUN path (apply / re-skip / --only / --force /
// broken-seeder catch), an api-snapshot compare that detects a breaking
// change, audit archive/export/verify-bundle/purge arg validation plus
// verify-chain FAIL and --max-rows branches, file-type edges, every
// `<cmd> help` positional, cheap arg-validation returns for the remaining
// commands, booted api-key / erase / retention / mtls / security edges,
// and repeatable-flag accumulation (--arg / --watch / --ignore).

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var sqlite = require("node:sqlite");
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var cli = require("../../lib/cli");

function _captureCtx() {
  var stdout = [];
  var stderr = [];
  return {
    stdout: { write: function (s) { stdout.push(String(s)); } },
    stderr: { write: function (s) { stderr.push(String(s)); } },
    env:    {},
    cwd:    process.cwd(),
    out:    function () { return stdout.join(""); },
    err:    function () { return stderr.join(""); },
  };
}

function _tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

function _rm(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

// ---------------------------------------------------------------------------
// top-level dispatch edges
// ---------------------------------------------------------------------------
async function sectionTopLevel() {
  // `-v` short flag → version (covers the `args.flags.v` operand of `||`)
  var cV = _captureCtx();
  var rcV = await cli.main(["-v"], cV);
  check("-v short flag → exit 0",            rcV === 0);
  check("-v short flag → prints version",    /\d+\.\d+\.\d+/.test(cV.out()));

  // `migrate help` positional → _runMigrate's own help branch (distinct from
  // the top-level `migrate --help` synth, which never enters _runMigrate).
  var cMh = _captureCtx();
  var rcMh = await cli.main(["migrate", "help"], cMh);
  check("migrate help positional → exit 0",  rcMh === 0);
  check("migrate help positional → usage",   /Usage: blamejs migrate/.test(cMh.out()));

  // bare `audit` → AUDIT_USAGE on stderr, exit 2
  var cAudit = _captureCtx();
  var rcAudit = await cli.main(["audit"], cAudit);
  check("bare audit → exit 2",               rcAudit === 2);
  check("bare audit → usage on stderr",      /Usage: blamejs audit/.test(cAudit.err()));

  // unknown audit subcommand → exit 2
  var cAuditUnk = _captureCtx();
  var rcAuditUnk = await cli.main(["audit", "frobnicate"], cAuditUnk);
  check("audit unknown sub → exit 2",        rcAuditUnk === 2);
  check("audit unknown sub → names sub",     /unknown subcommand 'frobnicate'/.test(cAuditUnk.err()));
}

// ---------------------------------------------------------------------------
// seed run — apply / re-skip / --only / --force / broken-seeder catch
// ---------------------------------------------------------------------------
async function sectionSeedRun() {
  var dir = _tmpDir("blamejs-cli-seed");
  try {
    var dbPath = path.join(dir, "seed.db");
    var seedRoot = path.join(dir, "seeders");
    var devDir = path.join(seedRoot, "dev");
    fs.mkdirSync(devDir, { recursive: true });
    fs.writeFileSync(path.join(devDir, "0001-alpha.js"),
      "module.exports = { description: \"a\", run: async function (db) {" +
      " db.exec(\"CREATE TABLE IF NOT EXISTS m_alpha (id INTEGER)\"); } };");
    fs.writeFileSync(path.join(devDir, "0002-beta.js"),
      "module.exports = { description: \"b\", rerunnable: true, run: async function (db) {" +
      " db.exec(\"CREATE TABLE IF NOT EXISTS m_beta (id INTEGER)\"); } };");

    // first run → both apply
    var c1 = _captureCtx();
    var r1 = await cli.main(["seed", "run", "--db", dbPath, "--env", "dev", "--dir", seedRoot], c1);
    check("seed run: first run → exit 0",         r1 === 0);
    check("seed run: applies 2 seeds",            /applied 2 seed\(s\)/.test(c1.out()));

    // status after run → applied rows loop + rerunnable listing
    var c2 = _captureCtx();
    var r2 = await cli.main(["seed", "status", "--db", dbPath, "--env", "dev", "--dir", seedRoot], c2);
    check("seed status (post-run): exit 0",       r2 === 0);
    check("seed status (post-run): env line",     /env: dev/.test(c2.out()));
    check("seed status (post-run): rerunnable",   /rerunnable:/.test(c2.out()));

    // second run → 0001 skipped, 0002 (rerunnable) re-applies
    var c3 = _captureCtx();
    var r3 = await cli.main(["seed", "run", "--db", dbPath, "--env", "dev", "--dir", seedRoot], c3);
    check("seed run: second run → exit 0",        r3 === 0);
    check("seed run: reports a skipped seed",     /skipped 1/.test(c3.out()));

    // --only an already-applied seed → nothing applied (only-branch)
    var c4 = _captureCtx();
    var r4 = await cli.main(
      ["seed", "run", "--db", dbPath, "--env", "dev", "--dir", seedRoot, "--only", "0001-alpha.js"], c4);
    check("seed run --only: exit 0",              r4 === 0);
    check("seed run --only: no re-apply",         /no seeds applied/.test(c4.out()));

    // --force → re-applies already-applied seeds (force-branch)
    var c5 = _captureCtx();
    var r5 = await cli.main(
      ["seed", "run", "--db", dbPath, "--env", "dev", "--dir", seedRoot, "--force"], c5);
    check("seed run --force: exit 0",             r5 === 0);
    check("seed run --force: applies again",      /applied \d+ seed\(s\)/.test(c5.out()));

    // broken seeder → run throws → the run catch returns exit 1
    var dir2 = _tmpDir("blamejs-cli-seed-broken");
    try {
      var db2 = path.join(dir2, "seed.db");
      var devDir2 = path.join(dir2, "seeders", "dev");
      fs.mkdirSync(devDir2, { recursive: true });
      fs.writeFileSync(path.join(devDir2, "0001-boom.js"),
        "module.exports = { description: \"x\", run: async function () {" +
        " throw new Error(\"boom-seed\"); } };");
      var c6 = _captureCtx();
      var r6 = await cli.main(
        ["seed", "run", "--db", db2, "--env", "dev", "--dir", path.join(dir2, "seeders")], c6);
      check("seed run: broken seeder → exit 1",   r6 === 1);
      check("seed run: broken seeder → stderr",   /blamejs seed run:/.test(c6.err()));
    } finally { _rm(dir2); }
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// api-snapshot compare that DETECTS a breaking change (exit 1)
// ---------------------------------------------------------------------------
async function sectionApiSnapshotBreaking() {
  var dir = _tmpDir("blamejs-cli-apisnap");
  try {
    var modA = path.join(dir, "mod-a.js");
    var modB = path.join(dir, "mod-b.js");
    var snap = path.join(dir, "snap.json");
    fs.writeFileSync(modA,
      "module.exports = { version: \"1.0.0\", greet: function greet() {}, extra: function extra() {} };");
    fs.writeFileSync(modB,
      "module.exports = { version: \"1.0.0\", greet: function greet() {} };");

    var cCap = _captureCtx();
    var rcCap = await cli.main(
      ["api-snapshot", "capture", "--file", snap, "--module", modA], cCap);
    check("api-snapshot capture (mod-a): exit 0", rcCap === 0);

    // mod-b dropped `extra` → removed export → breaking → exit 1
    var cCmp = _captureCtx();
    var rcCmp = await cli.main(
      ["api-snapshot", "compare", "--file", snap, "--module", modB], cCmp);
    check("api-snapshot compare breaking → exit 1", rcCmp === 1);
    check("api-snapshot compare breaking → reports it",
          /BREAKING|removed|extra/i.test(cCmp.out()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// audit — arg-validation returns + env passphrase + verify-chain FAIL / max-rows
// ---------------------------------------------------------------------------
async function sectionAudit() {
  var dir = _tmpDir("blamejs-cli-audit");
  try {
    var outDir = path.join(dir, "bundle-out");

    // archive: missing passphrase → 2
    var a1 = _captureCtx();
    check("audit archive no-pass → exit 2",
          (await cli.main(["audit", "archive", "--out", outDir, "--before", "2020-01-01"], a1)) === 2);
    check("audit archive no-pass → message", /--passphrase or BLAMEJS_AUDIT_PASSPHRASE/.test(a1.err()));

    // archive: passphrase but no --out → 2
    var a2 = _captureCtx();
    check("audit archive no-out → exit 2",
          (await cli.main(["audit", "archive", "--passphrase", "p", "--before", "2020-01-01"], a2)) === 2);
    check("audit archive no-out → message", /--out is required/.test(a2.err()));

    // archive: passphrase + out but no --before → 2
    var a3 = _captureCtx();
    check("audit archive no-before → exit 2",
          (await cli.main(["audit", "archive", "--passphrase", "p", "--out", outDir], a3)) === 2);
    check("audit archive no-before → message", /--before is required/.test(a3.err()));

    // export: passphrase but no --out → 2
    var e1 = _captureCtx();
    check("audit export no-out → exit 2",
          (await cli.main(["audit", "export", "--passphrase", "p"], e1)) === 2);
    check("audit export no-out → message", /--out is required/.test(e1.err()));

    // export: passphrase + out but no from/to/action → 2
    var e2 = _captureCtx();
    check("audit export no-range → exit 2",
          (await cli.main(["audit", "export", "--passphrase", "p", "--out", outDir], e2)) === 2);
    check("audit export no-range → message", /at least one of --from/.test(e2.err()));

    // verify-bundle: passphrase but no --in → 2
    var vb = _captureCtx();
    check("audit verify-bundle no-in → exit 2",
          (await cli.main(["audit", "verify-bundle", "--passphrase", "p"], vb)) === 2);
    check("audit verify-bundle no-in → message", /--in is required/.test(vb.err()));

    // purge: passphrase but no --archive → 2
    var p1 = _captureCtx();
    check("audit purge no-archive → exit 2",
          (await cli.main(["audit", "purge", "--passphrase", "p"], p1)) === 2);
    check("audit purge no-archive → message", /--archive .* is required/.test(p1.err()));

    // purge: passphrase + archive but no --confirm → 2
    var p2 = _captureCtx();
    check("audit purge no-confirm → exit 2",
          (await cli.main(["audit", "purge", "--passphrase", "p", "--archive", outDir], p2)) === 2);
    check("audit purge no-confirm → message", /--confirm is REQUIRED/.test(p2.err()));

    // env passphrase resolution: BLAMEJS_AUDIT_PASSPHRASE satisfies passRequired,
    // then archive fails on the missing --out (exit 2). Exercises the env branch
    // of _resolvePassphrase.
    var envCtx = _captureCtx();
    envCtx.env = { BLAMEJS_AUDIT_PASSPHRASE: "from-env" };
    var rcEnv = await cli.main(["audit", "archive", "--before", "2020-01-01"], envCtx);
    check("audit archive env-pass → past pass-gate to --out → exit 2", rcEnv === 2);
    check("audit archive env-pass → --out message", /--out is required/.test(envCtx.err()));

    // verify-chain: valid --max-rows applied against an empty audit_log (exit 0)
    var okDb = path.join(dir, "ok.db");
    var okHandle = new sqlite.DatabaseSync(okDb);
    okHandle.prepare("CREATE TABLE audit_log (_id INTEGER PRIMARY KEY, monotonicCounter INTEGER," +
      " prevHash TEXT, rowHash TEXT, nonce BLOB)").run();
    okHandle.close();
    var mr = _captureCtx();
    var rcMr = await cli.main(["audit", "verify-chain", "--db", okDb, "--max-rows", "5"], mr);
    check("audit verify-chain --max-rows valid → exit 0", rcMr === 0);
    check("audit verify-chain --max-rows valid → verified", /rowsVerified=0/.test(mr.out()));

    // verify-chain: a tampered first row (prevHash != ZERO_HASH) → FAIL, exit 1
    var badDb = path.join(dir, "bad.db");
    var badHandle = new sqlite.DatabaseSync(badDb);
    badHandle.prepare("CREATE TABLE audit_consent (_id INTEGER PRIMARY KEY, monotonicCounter INTEGER," +
      " prevHash TEXT, rowHash TEXT, nonce BLOB)").run();
    var ins = badHandle.prepare("INSERT INTO audit_consent" +
      " (_id, monotonicCounter, prevHash, rowHash, nonce) VALUES (?, ?, ?, ?, ?)");
    // prevHash of the FIRST row must be the all-zero sentinel; "ff"*64 is a
    // valid 128-hex string that is NOT the sentinel → guaranteed chain break.
    ins.run(1, 1, "ff".repeat(64), "aa".repeat(64), Buffer.alloc(16));
    badHandle.close();
    var fc = _captureCtx();
    var rcFc = await cli.main(
      ["audit", "verify-chain", "--db", badDb, "--table", "audit_consent"], fc);
    check("audit verify-chain tampered → exit 1", rcFc === 1);
    check("audit verify-chain tampered → FAIL line", /FAIL —/.test(fc.err()));
    check("audit verify-chain tampered → prints expected/actual", /expected prevHash:/.test(fc.err()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// file-type — bare / help / read-failure / json+allowlist / json-null
// ---------------------------------------------------------------------------
async function sectionFileType() {
  var dir = _tmpDir("blamejs-cli-filetype");
  try {
    var pngBytes = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
      Buffer.alloc(20),
    ]);
    var pngFile = path.join(dir, "img.png");
    fs.writeFileSync(pngFile, pngBytes);
    var unkFile = path.join(dir, "unk.bin");
    fs.writeFileSync(unkFile, Buffer.from("not-a-known-format-byte-stream-xyz"));

    // bare `file-type` → usage exit 2
    var bare = _captureCtx();
    check("file-type bare → exit 2", (await cli.main(["file-type"], bare)) === 2);
    check("file-type bare → usage", /Usage: blamejs file-type/.test(bare.err()));

    // `file-type help` positional → helpStdout exit 0
    var fh = _captureCtx();
    check("file-type help → exit 0", (await cli.main(["file-type", "help"], fh)) === 0);
    check("file-type help → usage", /Usage: blamejs file-type/.test(fh.out()));

    // detect a nonexistent path → read failure catch → exit 1
    var rf = _captureCtx();
    var rcRf = await cli.main(["file-type", "detect", path.join(dir, "nope.bin")], rf);
    check("file-type detect missing file → exit 1", rcRf === 1);
    check("file-type detect missing file → read failed", /read failed/.test(rf.err()));

    // json + allowlist match → the json arm of the allowlist branch
    var ja = _captureCtx();
    var rcJa = await cli.main(
      ["file-type", "detect", pngFile, "--json", "--allowlist", "image/png,application/pdf"], ja);
    check("file-type allowlist+json → exit 0", rcJa === 0);
    check("file-type allowlist+json → JSON body", /"mime":"image\/png"/.test(ja.out()));

    // json + unknown signature → prints "null" then errors (exit 1)
    var jn = _captureCtx();
    var rcJn = await cli.main(["file-type", "detect", unkFile, "--json"], jn);
    check("file-type json-null → exit 1", rcJn === 1);
    check("file-type json-null → 'null' on stdout", /null/.test(jn.out()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// `<cmd> help` positional — report.helpStdout for every reporter-backed command
// ---------------------------------------------------------------------------
async function sectionPositionalHelp() {
  var cmds = [
    ["restore",      /Usage: blamejs restore/],
    ["backup",       /Usage: blamejs backup/],
    ["mtls",         /Usage: blamejs mtls/],
    ["vault",        /Usage: blamejs vault/],
    ["api-key",      /Usage: blamejs api-key/],
    ["security",     /Usage: blamejs security/],
    ["config-drift", /Usage: blamejs config-drift/],
    ["retention",    /Usage: blamejs retention/],
    ["password",     /Usage: blamejs password/],
  ];
  for (var i = 0; i < cmds.length; i++) {
    var ctx = _captureCtx();
    var rc = await cli.main([cmds[i][0], "help"], ctx);
    check(cmds[i][0] + " help → exit 0", rc === 0);
    check(cmds[i][0] + " help → usage",  cmds[i][1].test(ctx.out()));
  }
}

// ---------------------------------------------------------------------------
// cheap arg-validation returns (no boot)
// ---------------------------------------------------------------------------
async function sectionArgValidation() {
  // bare subcommand-less usages → exit 2
  var bares = ["security", "config-drift", "retention", "password"];
  for (var i = 0; i < bares.length; i++) {
    var cb = _captureCtx();
    check("bare " + bares[i] + " → exit 2", (await cli.main([bares[i]], cb)) === 2);
  }

  // retention: missing --data-dir → 2
  var rNoDir = _captureCtx();
  check("retention preview no data-dir → exit 2",
        (await cli.main(["retention", "preview", "--table", "t", "--age-field", "a", "--ttl-ms", "1"], rNoDir)) === 2);

  // retention: missing --ttl-ms → 2
  var rNoTtl = _captureCtx();
  check("retention preview no ttl-ms → exit 2",
        (await cli.main(["retention", "preview", "--data-dir", "/tmp/x", "--table", "t", "--age-field", "a"], rNoTtl)) === 2);

  // api-key: missing --namespace → 2 (data-dir present)
  var kNoNs = _captureCtx();
  check("api-key issue no namespace → exit 2",
        (await cli.main(["api-key", "issue", "--data-dir", "/tmp/x"], kNoNs)) === 2);
  check("api-key issue no namespace → message", /--namespace/.test(kNoNs.err()));

  // api-key: bad --vault-mode → 2
  var kBadVm = _captureCtx();
  check("api-key bad vault-mode → exit 2",
        (await cli.main(["api-key", "issue", "--data-dir", "/tmp/x", "--namespace", "n", "--vault-mode", "yolo"], kBadVm)) === 2);
  check("api-key bad vault-mode → message", /--vault-mode/.test(kBadVm.err()));

  // erase: missing --data-dir (table/row/confirm all present) → 2
  var eNoDir = _captureCtx();
  check("erase no data-dir → exit 2",
        (await cli.main(["erase", "--table", "users", "--row-id", "r-1", "--confirm", "--vault-mode", "plaintext"], eNoDir)) === 2);
  check("erase no data-dir → message", /--data-dir/.test(eNoDir.err()));
}

// ---------------------------------------------------------------------------
// backup / restore validation + error catches (mostly no boot)
// ---------------------------------------------------------------------------
async function sectionBackupRestoreValidation() {
  var dir = _tmpDir("blamejs-cli-br");
  try {
    // --- backup ---
    // inspect: missing --bundle → 2
    var b1 = _captureCtx();
    check("backup inspect no bundle → exit 2", (await cli.main(["backup", "inspect"], b1)) === 2);
    check("backup inspect no bundle → message", /--bundle <dir> is required/.test(b1.err()));

    // inspect a nonexistent bundle → restoreBundle.inspect throws → catch → 1
    var b2 = _captureCtx();
    var rcB2 = await cli.main(["backup", "inspect", "--bundle", path.join(dir, "no-such-bundle")], b2);
    check("backup inspect bad bundle → exit 1", rcB2 === 1);

    // verify: missing passphrase → 2 (bundle present so passphrase gate is reached)
    var b3 = _captureCtx();
    check("backup verify no passphrase → exit 2",
          (await cli.main(["backup", "verify", "--bundle", path.join(dir, "b")], b3)) === 2);
    check("backup verify no passphrase → message", /--passphrase or BLAMEJS_BACKUP_PASSPHRASE/.test(b3.err()));

    // extract: passphrase present but missing --to → 2
    var b4 = _captureCtx();
    check("backup extract no --to → exit 2",
          (await cli.main(["backup", "extract", "--bundle", path.join(dir, "b"), "--passphrase", "p"], b4)) === 2);
    check("backup extract no --to → message", /--to <stagingDir> is required/.test(b4.err()));

    // --- restore ---
    // list with no selector → "--storage-root is required" → 2
    var r1 = _captureCtx();
    check("restore list no selector → exit 2", (await cli.main(["restore", "list"], r1)) === 2);
    check("restore list no selector → message", /--storage-root/.test(r1.err()));

    // inspect --storage-root without --bundle-id → 2
    var r2 = _captureCtx();
    check("restore inspect storage-root sans bundle-id → exit 2",
          (await cli.main(["restore", "inspect", "--storage-root", dir], r2)) === 2);
    check("restore inspect storage-root sans bundle-id → message", /--bundle-id is required/.test(r2.err()));

    // rollback with no --data-dir → 2
    var r3 = _captureCtx();
    check("restore rollback no data-dir → exit 2", (await cli.main(["restore", "rollback"], r3)) === 2);

    // list-rollbacks with no --data-dir → 2
    var r4 = _captureCtx();
    check("restore list-rollbacks no data-dir → exit 2", (await cli.main(["restore", "list-rollbacks"], r4)) === 2);

    // apply: valid selector + passphrase, but invalid --max-pulled-bytes → 2
    var r5 = _captureCtx();
    check("restore apply bad max-bytes → exit 2",
          (await cli.main(["restore", "apply", "--data-dir", path.join(dir, "dd"),
            "--bundle", path.join(dir, "bun"), "--passphrase", "p", "--max-pulled-bytes", "-1"], r5)) === 2);
    check("restore apply bad max-bytes → message", /--max-pulled-bytes/.test(r5.err()));

    // apply: invalid --max-pulled-files → 2
    var r6 = _captureCtx();
    check("restore apply bad max-files → exit 2",
          (await cli.main(["restore", "apply", "--data-dir", path.join(dir, "dd"),
            "--bundle", path.join(dir, "bun"), "--passphrase", "p", "--max-pulled-files", "-1"], r6)) === 2);
    check("restore apply bad max-files → message", /--max-pulled-files/.test(r6.err()));

    // rollback with an explicit --rollback that does not exist → primitive
    // throws → catch → non-zero (exercises the explicit-target branch).
    var ddEmpty = path.join(dir, "empty-data");
    fs.mkdirSync(ddEmpty, { recursive: true });
    var r7 = _captureCtx();
    var rcR7 = await cli.main(
      ["restore", "rollback", "--data-dir", ddEmpty, "--rollback", path.join(dir, "no-such-point")], r7);
    check("restore rollback bad explicit target → non-zero", rcR7 !== 0);
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// booted: api-key rotate + revoke no-op + empty-scopes
// ---------------------------------------------------------------------------
async function sectionBootedApiKey() {
  var dataDir = _tmpDir("blamejs-cli-apikey");
  try {
    var base = ["--data-dir", dataDir, "--vault-mode", "plaintext", "--namespace", "api"];

    // issue a key so rotate has something to rotate
    var ci = _captureCtx();
    var rci = await cli.main(["api-key", "issue"].concat(base).concat(
      ["--owner-id", "dave", "--scopes", "a:read"]), ci);
    check("apikey issue (for rotate): exit 0", rci === 0);
    var idMatch = ci.out().match(/^id:\s+([a-f0-9]+)/m);
    check("apikey issue: id captured", !!idMatch);
    var id = idMatch ? idMatch[1] : "deadbeef";
    var keyMatch = ci.out().match(/^key:\s+(\S+)/m);

    // list → owner header + active-key row loop (the list subcommand body)
    var cl = _captureCtx();
    var rcl = await cli.main(["api-key", "list"].concat(base).concat(["--owner-id", "dave"]), cl);
    check("apikey list: exit 0", rcl === 0);
    check("apikey list: owner header", /owner: dave \(\d+ active keys\)/.test(cl.out()));

    // verify a VALID composite token BEFORE rotate (rotate with default
    // gracePeriodMs=0 immediately invalidates the old secret) → success
    // path prints the resolved id / ownerId / scopes.
    if (keyMatch) {
      var cvf = _captureCtx();
      var rcvf = await cli.main(["api-key", "verify"].concat(base).concat(["--token", keyMatch[1]]), cvf);
      check("apikey verify valid → exit 0", rcvf === 0);
      check("apikey verify valid → prints ownerId", /ownerId:\s+dave/.test(cvf.out()));
    }

    // verify a syntactically-bogus token → registry.verify returns null →
    // report.error("rejected: ...") → non-zero.
    var cvb = _captureCtx();
    var rcvb = await cli.main(["api-key", "verify"].concat(base).concat(["--token", "not-a-real-token"]), cvb);
    check("apikey verify bogus → non-zero", rcvb !== 0);
    check("apikey verify bogus → rejected msg", /rejected: token does not verify/.test(cvb.err()));

    // rotate → new secret, exit 0 (the rotate subcommand is otherwise untested)
    var cr = _captureCtx();
    var rcr = await cli.main(["api-key", "rotate"].concat(base).concat(["--id", id]), cr);
    check("apikey rotate: exit 0", rcr === 0);
    check("apikey rotate: prints new key", /key \(new\):/.test(cr.out()));

    // revoke a nonexistent id → registry.revoke returns false → no-op error path
    var cx = _captureCtx();
    var rcx = await cli.main(["api-key", "revoke"].concat(base).concat(["--id", "00ffffffffffffff"]), cx);
    check("apikey revoke no-op → non-zero", rcx !== 0);
    check("apikey revoke no-op → message", /no-op/.test(cx.err()));

    // issue with scopes that parse to an empty list → exit 2 (post-boot check)
    var cs = _captureCtx();
    var rcs = await cli.main(["api-key", "issue"].concat(base).concat(
      ["--owner-id", "erin", "--scopes", ","]), cs);
    check("apikey issue empty-scopes → exit 2", rcs === 2);
    check("apikey issue empty-scopes → message", /at least one non-empty scope/.test(cs.err()));

    // post-boot required-flag checks that only fire AFTER a successful boot:
    // issue with no --owner-id and issue with no --scopes each return exit 2.
    var cNoOwner = _captureCtx();
    var rcNoOwner = await cli.main(["api-key", "issue"].concat(base).concat(["--scopes", "a:read"]), cNoOwner);
    check("apikey issue no owner-id (post-boot) → exit 2", rcNoOwner === 2);
    check("apikey issue no owner-id → message", /--owner-id <id> is required/.test(cNoOwner.err()));

    var cNoScopes = _captureCtx();
    var rcNoScopes = await cli.main(["api-key", "issue"].concat(base).concat(["--owner-id", "frank"]), cNoScopes);
    check("apikey issue no scopes (post-boot) → exit 2", rcNoScopes === 2);
    check("apikey issue no scopes → message", /--scopes <comma-separated> is required/.test(cNoScopes.err()));

    // issue WITH --label + --expires-ms → the metadata-label arm, the
    // expiresAt-mapping arm, and the "expires:" stdout line. The subsequent
    // list surfaces the per-row "expires=" branch, and verifying the composite
    // token twice stamps then prints "last-used:" + "expires:".
    var future = Date.now() + 1000 * 60 * 60 * 24;
    var ce = _captureCtx();
    var rce = await cli.main(["api-key", "issue"].concat(base).concat(
      ["--owner-id", "grace", "--scopes", "a:read,b:write", "--label", "ci-token",
       "--expires-ms", String(future)]), ce);
    check("apikey issue --label --expires-ms → exit 0", rce === 0);
    check("apikey issue --expires-ms → prints expires line", /^expires:\s+\d{4}-/m.test(ce.out()));
    var graceKey = ce.out().match(/^key:\s+(\S+)/m);

    var cle = _captureCtx();
    await cli.main(["api-key", "list"].concat(base).concat(["--owner-id", "grace"]), cle);
    check("apikey list → per-row expires= branch", /expires=\d{4}-/.test(cle.out()));

    if (graceKey) {
      // first verify stamps lastUsedAt; second verify prints both the
      // "last-used:" and "expires:" lines (v.lastUsedAt / v.expiresAt truthy).
      await cli.main(["api-key", "verify"].concat(base).concat(["--token", graceKey[1]]), _captureCtx());
      var cve = _captureCtx();
      var rcve = await cli.main(["api-key", "verify"].concat(base).concat(["--token", graceKey[1]]), cve);
      check("apikey verify (2nd) → exit 0", rcve === 0);
      check("apikey verify → prints last-used line", /last-used:\s+\d{4}-/.test(cve.out()));
      check("apikey verify → prints expires line", /expires:\s+\d{4}-/.test(cve.out()));
    }
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// booted: erase row-lookup-failure catch
// ---------------------------------------------------------------------------
async function sectionBootedErase() {
  var dataDir = _tmpDir("blamejs-cli-erase");
  try {
    // A syntactically-valid table identifier that does not exist → the SELECT
    // prepare throws → the "row lookup failed" catch returns exit 1.
    var ctx = _captureCtx();
    var rc = await cli.main(
      ["erase", "--data-dir", dataDir, "--table", "nonexistent_tbl", "--row-id", "r-1",
       "--confirm", "--vault-mode", "plaintext"], ctx);
    check("erase missing-table lookup → exit 1", rc === 1);
    check("erase missing-table lookup → catch message", /row lookup failed/.test(ctx.err()));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// booted: retention run against a missing table (boot + declare + run + error path)
// ---------------------------------------------------------------------------
async function sectionBootedRetention() {
  var dataDir = _tmpDir("blamejs-cli-retention");
  try {
    var ctx = _captureCtx();
    var rc = await cli.main(
      ["retention", "preview", "--data-dir", dataDir, "--vault-mode", "plaintext",
       "--table", "no_such_retention_tbl", "--age-field", "ts", "--ttl-ms", "1", "--action", "delete"], ctx);
    // The rule boots + declares + runs; a missing table surfaces as either a
    // per-row error summary (exit 1) or the outer catch (exit 1) — never a
    // bad-invocation (exit 2). Assert it got PAST validation into the run.
    check("retention preview missing-table → past validation (not exit 2)", rc !== 2);
    check("retention preview missing-table → exit 0 or 1", rc === 0 || rc === 1);
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// booted: mtls status(exists) / show-cert(success) / issue --days / issue-p12 stdout
// ---------------------------------------------------------------------------
async function sectionBootedMtls() {
  var dataDir = _tmpDir("blamejs-cli-mtls");
  try {
    var base = ["--data-dir", dataDir, "--vault-mode", "plaintext"];

    var ci = _captureCtx();
    check("mtls init: exit 0", (await cli.main(["mtls", "init"].concat(base), ci)) === 0);

    // status against an EXISTING CA → the `s.exists` true branch (generation + paths)
    var cs = _captureCtx();
    var rcs = await cli.main(["mtls", "status"].concat(base), cs);
    check("mtls status (CA exists): exit 0", rcs === 0);
    check("mtls status (CA exists): reports yes", /CA exists:\s+yes/.test(cs.out()));
    check("mtls status (CA exists): prints paths", /cert:/.test(cs.out()));

    // show-cert against an existing CA → success PEM branch
    var cc = _captureCtx();
    var rcc = await cli.main(["mtls", "show-cert"].concat(base), cc);
    check("mtls show-cert (CA exists): exit 0", rcc === 0);
    check("mtls show-cert (CA exists): prints PEM", /BEGIN CERTIFICATE/.test(cc.out()));

    // issue with --days → the days-truthy branch
    var cd = _captureCtx();
    var rcd = await cli.main(["mtls", "issue"].concat(base).concat(["--subject", "cn-a", "--days", "30"]), cd);
    check("mtls issue --days: exit 0", rcd === 0);
    check("mtls issue --days: prints cert", /BEGIN CERTIFICATE/.test(cd.out()));

    // issue-p12 WITHOUT --out → streams the p12 bytes to stdout
    var cp = _captureCtx();
    var rcp = await cli.main(["mtls", "issue-p12"].concat(base).concat(
      ["--subject", "cn-b", "--password", "p12-passphrase-abc"]), cp);
    check("mtls issue-p12 (stdout): exit 0", rcp === 0);
    check("mtls issue-p12 (stdout): prints fingerprint", /fingerprint \(sha3-512\)/.test(cp.out()));

    // issue-p12 WITH --out AND --days → atomicFile.writeSync writes the bundle
    // to disk (the `outPath` branch) and the `--days` truthy arm sets the leaf
    // validityDays (distinct from the default-validity stdout call above).
    var p12Out = path.join(dataDir, "client.p12");
    var co = _captureCtx();
    var rco = await cli.main(["mtls", "issue-p12"].concat(base).concat(
      ["--subject", "cn-c", "--password", "p12-passphrase-xyz", "--days", "45", "--out", p12Out]), co);
    check("mtls issue-p12 --out --days: exit 0", rco === 0);
    check("mtls issue-p12 --out --days: reports written path", /p12 written: /.test(co.out()));
    check("mtls issue-p12 --out --days: file exists on disk", fs.existsSync(p12Out));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// booted: security assert with --require-env / --forbid-env
// ---------------------------------------------------------------------------
async function sectionBootedSecurity() {
  var dataDir = _tmpDir("blamejs-cli-security");
  try {
    var ctx = _captureCtx();
    var rc = await cli.main(
      ["security", "assert", "--data-dir", dataDir, "--vault-mode", "plaintext",
       "--no-audit-signing", "--no-db-at-rest", "--no-ntp-strict",
       "--require-env", "BLAMEJS_DEFINITELY_UNSET_XYZ",
       "--forbid-env", "BLAMEJS_ANOTHER_UNSET_ABC"], ctx);
    // plaintext vault vs the asserted "wrapped" posture + the unset required
    // env fail the assertion → FAIL summary, exit 1.
    check("security assert require/forbid-env → exit 1", rc === 1);
    check("security assert require/forbid-env → FAIL summary", /FAIL:/.test(ctx.out()));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// repeatable flags — a duplicated --arg / --watch / --ignore must accumulate
// every occurrence into an array, not collapse to the last one. Regression
// for the dev-command repeatable-flag drop: parseRaw overwrote flags[name] on
// repeat, so only the LAST --watch dir was monitored, the LAST --ignore
// applied, and only the LAST --arg reached the spawned child — every earlier
// occurrence was silently dropped even though DEV_USAGE documents all three
// as "(repeatable)".
// ---------------------------------------------------------------------------
function sectionRepeatableFlags() {
  // Public primitive: b.argParser.parseRaw (the splitter lib/cli.js runs).
  var r = b.argParser.parseRaw(
    ["dev", "--command", "node",
     "--arg", "x", "--arg", "y", "--arg", "z",
     "--watch", "./a", "--watch", "./b",
     "--ignore", "p1", "--ignore", "p2"]);
  check("parseRaw: repeated --arg accumulates in order",
    Array.isArray(r.flags.arg) && r.flags.arg.join(",") === "x,y,z");
  check("parseRaw: repeated --watch accumulates in order",
    Array.isArray(r.flags.watch) && r.flags.watch.join(",") === "./a,./b");
  check("parseRaw: repeated --ignore accumulates in order",
    Array.isArray(r.flags.ignore) && r.flags.ignore.join(",") === "p1,p2");
  // A flag seen once stays a scalar — non-repeatable flags are unaffected.
  check("parseRaw: single --command stays a scalar string", r.flags.command === "node");

  // Consumer path: cli._parseArgs is the exact splitter main() runs before
  // dispatching to _runDev, which reads args.flags.watch / .arg / .ignore and
  // funnels each through _coerceList. An array here is what _runDev needs so
  // it watches BOTH dirs and forwards BOTH args to the child.
  var a = cli._parseArgs(
    ["--command", "node", "--watch", "one", "--watch", "two",
     "--arg", "a1", "--arg", "a2"]);
  check("_parseArgs: --watch reaches _runDev as an ordered array",
    Array.isArray(a.flags.watch) && a.flags.watch.length === 2 &&
    a.flags.watch[0] === "one" && a.flags.watch[1] === "two");
  check("_parseArgs: --arg reaches _runDev as an ordered array",
    Array.isArray(a.flags.arg) && a.flags.arg.length === 2 &&
    a.flags.arg[0] === "a1" && a.flags.arg[1] === "a2");

  // The `--flag=value` form repeats accumulate too — including child flags
  // passed as `--arg=--inspect` (a value that itself starts with "--").
  var eqArg = b.argParser.parseRaw(["--arg=--inspect", "--arg=--port=3000"]);
  check("parseRaw: repeated --arg=VALUE accumulates (dash-valued children)",
    Array.isArray(eqArg.flags.arg) &&
    eqArg.flags.arg.join("|") === "--inspect|--port=3000");

  // Single occurrence of a value flag stays a plain string, not a 1-element
  // array — _coerceList wraps it, so the shape contract downstream is scalar.
  var one = b.argParser.parseRaw(["--watch", "./only"]);
  check("parseRaw: single --watch stays a string", one.flags.watch === "./only");
}

// ---------------------------------------------------------------------------
// migrate — the whole _runMigrate body (up / down / status / no-op / bad-steps
// / cannot-open / broken-migration catch) against a local temp sqlite file.
// Structurally identical to the seed section already in this file; the CLI
// opens its own raw node:sqlite handle via _openSqlite, so no framework boot.
// ---------------------------------------------------------------------------
async function sectionMigrate() {
  var dir = _tmpDir("blamejs-cli-migrate");
  try {
    var dbPath = path.join(dir, "mig.db");
    var migDir = path.join(dir, "migrations");
    fs.mkdirSync(migDir, { recursive: true });
    fs.writeFileSync(path.join(migDir, "0001-foo.js"),
      "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE foo (id INTEGER)\"); }," +
      " down: function (db) { db['exec'](\"DROP TABLE foo\"); } };");
    fs.writeFileSync(path.join(migDir, "0002-bar.js"),
      "module.exports = { up: function (db) { db['exec'](\"CREATE TABLE bar (id INTEGER)\"); }," +
      " down: function (db) { db['exec'](\"DROP TABLE bar\"); } };");

    // bare `migrate` (no subcommand) → usage on stderr, exit 2
    var cbare = _captureCtx();
    check("migrate bare: exit 2", (await cli.main(["migrate"], cbare)) === 2);
    check("migrate bare: usage", /Usage: blamejs migrate/.test(cbare.err()));

    // unknown subcommand → error + usage, exit 2
    var cunk = _captureCtx();
    check("migrate unknown sub: exit 2", (await cli.main(["migrate", "frobnicate"], cunk)) === 2);
    check("migrate unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));

    // known subcommand but missing --db → exit 2
    var cnodb = _captureCtx();
    check("migrate status no --db: exit 2", (await cli.main(["migrate", "status"], cnodb)) === 2);
    check("migrate status no --db: message", /--db <path> is required/.test(cnodb.err()));

    // status before any apply → 0/2 applied + pending listing loop
    var cs = _captureCtx();
    var rcs = await cli.main(["migrate", "status", "--db", dbPath, "--dir", migDir], cs);
    check("migrate status (pre): exit 0", rcs === 0);
    check("migrate status (pre): 0/2 applied", /applied: 0 \/ 2/.test(cs.out()));
    check("migrate status (pre): lists pending", /0001-foo\.js/.test(cs.out()) && /0002-bar\.js/.test(cs.out()));

    // up → applies both (the applied-count loop)
    var cu = _captureCtx();
    var rcu = await cli.main(["migrate", "up", "--db", dbPath, "--dir", migDir], cu);
    check("migrate up: exit 0", rcu === 0);
    check("migrate up: applies 2", /applied 2 migration/.test(cu.out()));

    // status after up → applied-rows loop (the ✓ lines)
    var cs2 = _captureCtx();
    await cli.main(["migrate", "status", "--db", dbPath, "--dir", migDir], cs2);
    check("migrate status (post): 2/2 applied", /applied: 2 \/ 2/.test(cs2.out()));

    // up again → no-pending branch
    var cu2 = _captureCtx();
    var rcu2 = await cli.main(["migrate", "up", "--db", dbPath, "--dir", migDir], cu2);
    check("migrate up again: exit 0", rcu2 === 0);
    check("migrate up again: no pending", /no pending migrations/.test(cu2.out()));

    // down --steps 1 → reverts most-recent (the reverted-count loop)
    var cd = _captureCtx();
    var rcd = await cli.main(["migrate", "down", "--db", dbPath, "--dir", migDir, "--steps", "1"], cd);
    check("migrate down --steps 1: exit 0", rcd === 0);
    check("migrate down --steps 1: reverts bar", /reverted 1 migration/.test(cd.out()) && /0002-bar\.js/.test(cd.out()));

    // down with no --steps → default 1
    var cd2 = _captureCtx();
    var rcd2 = await cli.main(["migrate", "down", "--db", dbPath, "--dir", migDir], cd2);
    check("migrate down (default steps): reverts foo", rcd2 === 0 && /0001-foo\.js/.test(cd2.out()));

    // down again on a fully-reverted db → nothing-to-revert branch
    var cd3 = _captureCtx();
    var rcd3 = await cli.main(["migrate", "down", "--db", dbPath, "--dir", migDir], cd3);
    check("migrate down (empty): nothing to revert", rcd3 === 0 && /nothing to revert/.test(cd3.out()));

    // --steps 0 → positive-integer validation → exit 2
    var cbad = _captureCtx();
    var rcbad = await cli.main(["migrate", "down", "--db", dbPath, "--dir", migDir, "--steps", "0"], cbad);
    check("migrate down --steps 0: exit 2", rcbad === 2);
    check("migrate down --steps 0: message", /--steps must be a positive integer/.test(cbad.err()));

    // unopenable db (parent dir absent) → _openSqlite throws → exit 1
    var copen = _captureCtx();
    var rcopen = await cli.main(
      ["migrate", "status", "--db", path.join(dir, "no-such-dir", "x.db"), "--dir", migDir], copen);
    check("migrate status unopenable db: exit 1", rcopen === 1);
    check("migrate status unopenable db: message", /cannot open db/.test(copen.err()));

    // a migration whose up() throws → runner.up() rejects → the run catch
    // returns exit 1 with the code:message shape.
    var dir2 = _tmpDir("blamejs-cli-migrate-boom");
    try {
      var db2 = path.join(dir2, "mig.db");
      var migDir2 = path.join(dir2, "migrations");
      fs.mkdirSync(migDir2, { recursive: true });
      fs.writeFileSync(path.join(migDir2, "0001-boom.js"),
        "module.exports = { up: function () { throw new Error(\"boom-mig\"); } };");
      var cboom = _captureCtx();
      var rcboom = await cli.main(["migrate", "up", "--db", db2, "--dir", migDir2], cboom);
      check("migrate up broken migration: exit 1", rcboom === 1);
      check("migrate up broken migration: stderr", /blamejs migrate up:/.test(cboom.err()));
    } finally { _rm(dir2); }
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// api-snapshot — bare usage / unknown subcommand / non-breaking compare (exit 0)
// / compare where the saved-snapshot READ itself fails.
// ---------------------------------------------------------------------------
async function sectionApiSnapshotEdges() {
  var dir = _tmpDir("blamejs-cli-apisnap2");
  try {
    // bare `api-snapshot` (no subcommand) → usage on stderr, exit 2
    var cbare = _captureCtx();
    var rcbare = await cli.main(["api-snapshot"], cbare);
    check("api-snapshot bare: exit 2", rcbare === 2);
    check("api-snapshot bare: usage on stderr", /Usage: blamejs api-snapshot/.test(cbare.err()));

    // unknown subcommand → exit 2
    var cunk = _captureCtx();
    var rcunk = await cli.main(["api-snapshot", "frobnicate"], cunk);
    check("api-snapshot unknown sub: exit 2", rcunk === 2);
    check("api-snapshot unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));

    // capture then compare against the SAME module → no diff → exit 0 (the
    // non-breaking return path, distinct from the breaking exit-1 case).
    var mod = path.join(dir, "mod.js");
    fs.writeFileSync(mod, "module.exports = { version: \"2.0.0\", greet: function greet() {} };");
    var snap = path.join(dir, "snap.json");
    var ccap = _captureCtx();
    check("api-snapshot capture (same-mod): exit 0",
      (await cli.main(["api-snapshot", "capture", "--file", snap, "--module", mod], ccap)) === 0);
    var ccmp = _captureCtx();
    var rccmp = await cli.main(["api-snapshot", "compare", "--file", snap, "--module", mod], ccmp);
    check("api-snapshot compare no-change: exit 0", rccmp === 0);

    // capture with NO --module → the default-module branch loads the
    // framework root index.js (operator-omitted-flag default path).
    var defSnap = path.join(dir, "default-snap.json");
    var cdef = _captureCtx();
    var rcdef = await cli.main(["api-snapshot", "capture", "--file", defSnap], cdef);
    check("api-snapshot capture (default module): exit 0", rcdef === 0);
    check("api-snapshot capture (default module): wrote file", fs.existsSync(defSnap));

    // compare where the saved snapshot file cannot be READ → the read catch
    // (distinct from the capture-current-surface catch) → exit 1.
    var cread = _captureCtx();
    var rcread = await cli.main(
      ["api-snapshot", "compare", "--file", path.join(dir, "no-such-snap.json"), "--module", mod], cread);
    check("api-snapshot compare unreadable snap: exit 1", rcread === 1);
    check("api-snapshot compare unreadable snap: message", /api-snapshot compare:/.test(cread.err()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// audit verify-chain — arg-validation + defensive open/query branches.
// ---------------------------------------------------------------------------
async function sectionAuditVerifyChainEdges() {
  var dir = _tmpDir("blamejs-cli-audit-vc");
  try {
    // missing --db → exit 2
    var cnodb = _captureCtx();
    var rcnodb = await cli.main(["audit", "verify-chain"], cnodb);
    check("verify-chain no --db: exit 2", rcnodb === 2);
    check("verify-chain no --db: message", /--db <path> is required/.test(cnodb.err()));

    // --max-rows 0 → positive-integer validation → exit 2
    var okDb = path.join(dir, "ok.db");
    var h = new sqlite.DatabaseSync(okDb);
    h.prepare("CREATE TABLE audit_log (_id INTEGER PRIMARY KEY, monotonicCounter INTEGER," +
      " prevHash TEXT, rowHash TEXT, nonce BLOB)").run();
    h.close();
    var cmr = _captureCtx();
    var rcmr = await cli.main(["audit", "verify-chain", "--db", okDb, "--max-rows", "0"], cmr);
    check("verify-chain --max-rows 0: exit 2", rcmr === 2);
    check("verify-chain --max-rows 0: message", /--max-rows must be a positive integer/.test(cmr.err()));

    // --max-rows 2.5 → the error message promises "a positive integer", so a
    // fractional value MUST be refused with exit 2 — matching the sibling
    // `migrate down --steps 2.5` guard. Before the fix, verify-chain only
    // screened `< 1` (not non-integer), so 2.5 slipped through, walked the
    // chain, and reported the nonsensical `rowsVerified=2.5` from
    // Math.min(rows.length, 2.5). Drive the real b.cli consumer path.
    var cfrac = _captureCtx();
    var rcfrac = await cli.main(["audit", "verify-chain", "--db", okDb, "--max-rows", "2.5"], cfrac);
    check("verify-chain --max-rows 2.5: exit 2", rcfrac === 2);
    check("verify-chain --max-rows 2.5: rejected (never verifies)", !/rowsVerified/.test(cfrac.out()));
    check("verify-chain --max-rows 2.5: message", /--max-rows must be a positive integer/.test(cfrac.err()));

    // a whole-number float string like "3.0" is an integer value → still valid
    // (Math.floor(3) === 3), exercising the accepted-integer arm after the fix.
    var cwhole = _captureCtx();
    var rcwhole = await cli.main(["audit", "verify-chain", "--db", okDb, "--max-rows", "3"], cwhole);
    check("verify-chain --max-rows 3 (integer): exit 0", rcwhole === 0);
    check("verify-chain --max-rows 3 (integer): verifies", /rowsVerified=0/.test(cwhole.out()));

    // unopenable db (parent dir absent) → _openSqlite throws → exit 1
    var copen = _captureCtx();
    var rcopen = await cli.main(
      ["audit", "verify-chain", "--db", path.join(dir, "no-dir", "x.db")], copen);
    check("verify-chain unopenable db: exit 1", rcopen === 1);
    check("verify-chain unopenable db: message", /cannot open db at/.test(copen.err()));

    // db opens but the audit table does not exist → the queryAllAsync prepare
    // throws inside the try → the outer catch returns exit 1.
    var emptyDb = path.join(dir, "empty.db");
    var h2 = new sqlite.DatabaseSync(emptyDb);
    h2.prepare("CREATE TABLE unrelated (id INTEGER)").run();
    h2.close();
    var cq = _captureCtx();
    var rcq = await cli.main(
      ["audit", "verify-chain", "--db", emptyDb, "--table", "audit_log"], cq);
    check("verify-chain missing table: exit 1", rcq === 1);
    check("verify-chain missing table: message", /blamejs audit verify-chain:/.test(cq.err()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// restore — bare / unknown-sub / list(empty) / inspect(bad-bundle catch) /
// apply(no-passphrase) / rollback(default-no-points) / list-rollbacks(empty).
// Everything below drives the real b.backup.diskStorage + b.restoreRollback
// primitives; none needs a live network or a decryptable bundle.
// ---------------------------------------------------------------------------
async function sectionRestoreEdges() {
  var dir = _tmpDir("blamejs-cli-restore2");
  try {
    // bare `restore` → usage, exit 2
    var cbare = _captureCtx();
    check("restore bare: exit 2", (await cli.main(["restore"], cbare)) === 2);
    check("restore bare: usage", /Usage: blamejs restore/.test(cbare.err()));

    // unknown subcommand → error + usage, exit 2
    var cunk = _captureCtx();
    check("restore unknown sub: exit 2", (await cli.main(["restore", "frobnicate"], cunk)) === 2);
    check("restore unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));

    // inspect with NEITHER --bundle NOR --storage-root → the requireBundle
    // "--bundle OR --storage-root ..." selector error, exit 2.
    var cnosel = _captureCtx();
    check("restore inspect (no selector): exit 2", (await cli.main(["restore", "inspect"], cnosel)) === 2);
    check("restore inspect (no selector): message",
      /--bundle <dir> OR --storage-root/.test(cnosel.err()));

    // list against an empty storage root → "no bundles" success path
    var store = path.join(dir, "store");
    fs.mkdirSync(store, { recursive: true });
    var cl = _captureCtx();
    var rcl = await cli.main(["restore", "list", "--storage-root", store], cl);
    check("restore list (empty store): exit 0", rcl === 0);
    check("restore list (empty store): no bundles line", /no bundles in /.test(cl.out()));

    // inspect a nonexistent bundle-id under a valid storage root → the
    // restore.create().inspect() rejects → the catch returns exit 1.
    var ci = _captureCtx();
    var rci = await cli.main(
      ["restore", "inspect", "--storage-root", store, "--bundle-id", "nope"], ci);
    check("restore inspect (missing bundle): exit 1", rci === 1);
    check("restore inspect (missing bundle): reports it", /blamejs restore inspect:/.test(ci.err()));

    // apply with a valid selector + data-dir but NO passphrase → the
    // passphrase gate returns exit 2 (distinct from the max-pulled-* gates).
    var ca = _captureCtx();
    var rca = await cli.main(
      ["restore", "apply", "--data-dir", path.join(dir, "dd"),
       "--bundle", path.join(dir, "bun")], ca);
    check("restore apply (no passphrase): exit 2", rca === 2);
    check("restore apply (no passphrase): message",
      /--passphrase or BLAMEJS_BACKUP_PASSPHRASE is required/.test(ca.err()));

    // rollback WITHOUT --rollback, against a data-dir with no rollback points →
    // the default "most-recent" branch finds none → exit 2 with the explicit
    // "pass --rollback" hint.
    var dd = path.join(dir, "dd-empty");
    fs.mkdirSync(dd, { recursive: true });
    var crb = _captureCtx();
    var rcrb = await cli.main(["restore", "rollback", "--data-dir", dd], crb);
    check("restore rollback (no points): exit 2", rcrb === 2);
    check("restore rollback (no points): hint", /no rollback points at .* pass --rollback/.test(crb.err()));

    // list-rollbacks against a data-dir with no rollback points → empty path,
    // exit 0.
    var clr = _captureCtx();
    var rclr = await cli.main(["restore", "list-rollbacks", "--data-dir", dd], clr);
    check("restore list-rollbacks (empty): exit 0", rclr === 0);
    check("restore list-rollbacks (empty): no points line", /no rollback points at /.test(clr.out()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// backup — bare usage + unknown subcommand (cheap dispatch edges; the
// decrypt/inspect success paths need a real encrypted bundle → out of scope
// for an in-process test).
// ---------------------------------------------------------------------------
async function sectionBackupEdges() {
  var cbare = _captureCtx();
  check("backup bare: exit 2", (await cli.main(["backup"], cbare)) === 2);
  check("backup bare: usage", /Usage: blamejs backup/.test(cbare.err()));

  var cunk = _captureCtx();
  check("backup unknown sub: exit 2", (await cli.main(["backup", "frobnicate"], cunk)) === 2);
  check("backup unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));
}

// ---------------------------------------------------------------------------
// mtls — dispatch + flag validation + boot-failure + not-yet-initialised CA
// branches. status(no-CA) / show-cert(no-CA) boot a plaintext app on a fresh
// data dir; the wrapped-boot-failure path uses an empty ctx.env so bootApp
// throws on the missing passphrase and the catch reports "boot failed".
// ---------------------------------------------------------------------------
async function sectionMtlsEdges() {
  var dir = _tmpDir("blamejs-cli-mtls2");
  try {
    // bare → usage, exit 2
    var cbare = _captureCtx();
    check("mtls bare: exit 2", (await cli.main(["mtls"], cbare)) === 2);
    check("mtls bare: usage", /Usage: blamejs mtls/.test(cbare.err()));

    // unknown subcommand → exit 2
    var cunk = _captureCtx();
    check("mtls unknown sub: exit 2", (await cli.main(["mtls", "frobnicate"], cunk)) === 2);

    // missing --data-dir → exit 2
    var cnodir = _captureCtx();
    check("mtls no data-dir: exit 2", (await cli.main(["mtls", "status"], cnodir)) === 2);
    check("mtls no data-dir: message", /--data-dir <path> is required/.test(cnodir.err()));

    // bad --vault-mode → exit 2
    var cvm = _captureCtx();
    check("mtls bad vault-mode: exit 2",
      (await cli.main(["mtls", "status", "--data-dir", dir, "--vault-mode", "yolo"], cvm)) === 2);
    check("mtls bad vault-mode: message", /--vault-mode must be/.test(cvm.err()));

    // bad --sealed-mode → exit 2
    var csm = _captureCtx();
    check("mtls bad sealed-mode: exit 2",
      (await cli.main(["mtls", "status", "--data-dir", dir, "--vault-mode", "plaintext",
        "--sealed-mode", "bogus"], csm)) === 2);
    check("mtls bad sealed-mode: message", /--sealed-mode must be/.test(csm.err()));

    // default vault-mode is wrapped; empty ctx.env → bootApp throws → catch
    // reports "boot failed" (exit 1).
    var cboot = _captureCtx();
    var rcboot = await cli.main(["mtls", "status", "--data-dir", dir], cboot);
    check("mtls wrapped-boot-fail: exit 1", rcboot === 1);
    check("mtls wrapped-boot-fail: message", /boot failed/.test(cboot.err()));

    // status on a fresh (never-initialised) data dir → the CA-absent branch.
    var fresh = _tmpDir("blamejs-cli-mtls2-fresh");
    try {
      var cst = _captureCtx();
      var rcst = await cli.main(["mtls", "status", "--data-dir", fresh, "--vault-mode", "plaintext"], cst);
      check("mtls status (no CA): exit 0", rcst === 0);
      check("mtls status (no CA): reports no", /CA exists:\s+no/.test(cst.out()));
      check("mtls status (no CA): hints init", /run 'blamejs mtls init'/.test(cst.out()));

      // show-cert with no CA on disk → error, exit 1.
      var csc = _captureCtx();
      var rcsc = await cli.main(["mtls", "show-cert", "--data-dir", fresh, "--vault-mode", "plaintext"], csc);
      check("mtls show-cert (no CA): exit 1", rcsc === 1);
      check("mtls show-cert (no CA): message", /no CA on disk/.test(csc.err()));
    } finally { _rm(fresh); }
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// security — dispatch + flag validation + boot-failure.
// ---------------------------------------------------------------------------
async function sectionSecurityEdges() {
  var dir = _tmpDir("blamejs-cli-sec2");
  try {
    var cunk = _captureCtx();
    check("security unknown sub: exit 2", (await cli.main(["security", "frobnicate"], cunk)) === 2);
    check("security unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));

    var cnodir = _captureCtx();
    check("security no data-dir: exit 2", (await cli.main(["security", "assert"], cnodir)) === 2);
    check("security no data-dir: message", /--data-dir <path> is required/.test(cnodir.err()));

    var cvm = _captureCtx();
    check("security bad vault-mode: exit 2",
      (await cli.main(["security", "assert", "--data-dir", dir, "--vault-mode", "yolo"], cvm)) === 2);

    // wrapped (default) + empty env → boot fails → exit 1
    var cboot = _captureCtx();
    var rcboot = await cli.main(["security", "assert", "--data-dir", dir], cboot);
    check("security wrapped-boot-fail: exit 1", rcboot === 1);
    check("security wrapped-boot-fail: message", /boot failed/.test(cboot.err()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// config-drift — dispatch + flag validation + boot-failure + the no-sidecar
// read branch (verify → exit 1, inspect → exit 0) on a freshly-booted app.
// ---------------------------------------------------------------------------
async function sectionConfigDrift() {
  var dir = _tmpDir("blamejs-cli-drift");
  try {
    var cunk = _captureCtx();
    check("config-drift unknown sub: exit 2", (await cli.main(["config-drift", "frobnicate"], cunk)) === 2);
    check("config-drift unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));

    var cnodir = _captureCtx();
    check("config-drift no data-dir: exit 2", (await cli.main(["config-drift", "verify"], cnodir)) === 2);
    check("config-drift no data-dir: message", /--data-dir <path> is required/.test(cnodir.err()));

    // wrapped (default) + empty env → boot fails → exit 1
    var cboot = _captureCtx();
    var rcboot = await cli.main(["config-drift", "verify", "--data-dir", dir], cboot);
    check("config-drift wrapped-boot-fail: exit 1", rcboot === 1);
    check("config-drift wrapped-boot-fail: message", /boot failed/.test(cboot.err()));

    // Fresh plaintext boot with no captured sidecar → verify returns exit 1,
    // inspect returns exit 0, both printing "no sidecar present".
    var fresh = _tmpDir("blamejs-cli-drift-fresh");
    try {
      var cv = _captureCtx();
      var rcv = await cli.main(["config-drift", "verify", "--data-dir", fresh, "--vault-mode", "plaintext"], cv);
      check("config-drift verify (no sidecar): exit 1", rcv === 1);
      check("config-drift verify (no sidecar): message", /no sidecar present/.test(cv.out()));

      // inspect with an explicit --baseline exercises the baseline-opt branch
      // (still no sidecar under that baseline → exit 0).
      var cin = _captureCtx();
      var rcin = await cli.main(
        ["config-drift", "inspect", "--data-dir", fresh, "--vault-mode", "plaintext", "--baseline", "custom"], cin);
      check("config-drift inspect (no sidecar): exit 0", rcin === 0);
      check("config-drift inspect (no sidecar): message", /no sidecar present/.test(cin.out()));
    } finally { _rm(fresh); }
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// config-drift — the sidecar-PRESENT branches (verified-yes + inspect JSON +
// inspect snapshot text). A signed baseline is captured out-of-band through
// the real b.configDrift primitive on the same data-dir, then fully shut down
// before the CLI boots the same dir (the CLI loads the persisted audit-signing
// key, so the sidecar verifies). Covers the block the no-sidecar section
// (which returns early at "no sidecar present") never reaches.
// ---------------------------------------------------------------------------
async function sectionConfigDriftSidecar() {
  var dataDir = _tmpDir("blamejs-cli-drift-sc");
  try {
    var booted = await b.cliHelpers.bootApp({ dataDir: dataDir, vaultMode: "plaintext", env: {} });
    try {
      var drift = booted.b.configDrift.create({ dataDir: dataDir, audit: booted.b.audit });
      var res = await drift.checkpoint({ service: "web", replicas: 3 });
      check("config-drift sidecar: baseline captured", res && res.signed === true && res.tamper === false);
    } finally {
      try { await booted.app.shutdown(); } catch (_e) { /* best-effort */ }
    }

    // inspect (text) → verified-yes branch + capturedAt/digest/snapshot printing
    var ci = _captureCtx();
    var rci = await cli.main(
      ["config-drift", "inspect", "--data-dir", dataDir, "--vault-mode", "plaintext"], ci);
    check("config-drift inspect (sidecar): exit 0", rci === 0);
    check("config-drift inspect (sidecar): capturedAt line", /capturedAt:/.test(ci.out()));
    check("config-drift inspect (sidecar): verified yes", /verified:\s+yes/.test(ci.out()));
    check("config-drift inspect (sidecar): prints snapshot", /"service": "web"/.test(ci.out()));

    // inspect --json → the JSON arm (machine-readable verified flag)
    var cj = _captureCtx();
    var rcj = await cli.main(
      ["config-drift", "inspect", "--data-dir", dataDir, "--vault-mode", "plaintext", "--json"], cj);
    check("config-drift inspect --json (sidecar): exit 0", rcj === 0);
    check("config-drift inspect --json (sidecar): verified true", /"verified":\s*true/.test(cj.out()));

    // verify → the verified-success branch (exit 0 + "sidecar verified at")
    var cv = _captureCtx();
    var rcv = await cli.main(
      ["config-drift", "verify", "--data-dir", dataDir, "--vault-mode", "plaintext"], cv);
    check("config-drift verify (sidecar): exit 0", rcv === 0);
    check("config-drift verify (sidecar): verified message", /sidecar verified at/.test(cv.out()));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// vault — the whole _runVault body: dispatch, status(fresh), seal(no-pass /
// success / keep-plaintext / already-sealed catch), unseal(no-pass / success),
// rotate(missing-new-pass / success). Drives b.vaultPassphraseOps through the
// CLI. A plaintext vault.key is created up-front via b.vault.init({ mode:
// "plaintext" }); the vault singleton is reset afterward so later booted
// sections re-init cleanly.
// ---------------------------------------------------------------------------
async function sectionVault() {
  var dir = _tmpDir("blamejs-cli-vault");
  var savedPass = process.env.BLAMEJS_VAULT_PASSPHRASE;
  var PP = "vault-cli-old-passphrase-123456";
  var NP = "vault-cli-new-passphrase-654321";
  try {
    // bare → usage, exit 2
    var cbare = _captureCtx();
    check("vault bare: exit 2", (await cli.main(["vault"], cbare)) === 2);
    check("vault bare: usage", /Usage: blamejs vault/.test(cbare.err()));

    // unknown subcommand → exit 2
    var cunk = _captureCtx();
    check("vault unknown sub: exit 2", (await cli.main(["vault", "frobnicate"], cunk)) === 2);
    check("vault unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));

    // status on a dir with neither key → both "absent", exit 0
    var cst = _captureCtx();
    var rcst = await cli.main(["vault", "status", "--data-dir", dir], cst);
    check("vault status (fresh): exit 0", rcst === 0);
    check("vault status (fresh): plaintext absent", /vault\.key \(plaintext\):\s+absent/.test(cst.out()));

    // seal with no passphrase → exit 2 (before any key exists)
    var cnp = _captureCtx();
    var rcnp = await cli.main(["vault", "seal", "--data-dir", dir], cnp);
    check("vault seal (no pass): exit 2", rcnp === 2);
    check("vault seal (no pass): message", /--passphrase or BLAMEJS_VAULT_PASSPHRASE is required/.test(cnp.err()));

    // create a plaintext vault.key to seal (init in plaintext mode writes it)
    delete process.env.BLAMEJS_VAULT_PASSPHRASE;
    b.vault._resetForTest();
    await b.vault.init({ dataDir: dir, mode: "plaintext" });
    b.vault._resetForTest();

    // seal → wraps + deletes plaintext, exit 0
    var cse = _captureCtx();
    var rcse = await cli.main(["vault", "seal", "--data-dir", dir, "--passphrase", PP], cse);
    check("vault seal: exit 0", rcse === 0);
    check("vault seal: reports sealed path", /sealed: /.test(cse.out()));
    check("vault seal: removed plaintext", /removed plaintext vault\.key/.test(cse.out()));

    // status now reports the sealed file present
    var cst2 = _captureCtx();
    await cli.main(["vault", "status", "--data-dir", dir], cst2);
    check("vault status (sealed): sealed present", /vault\.key\.sealed \(wrapped\): present/.test(cst2.out()));

    // seal AGAIN (plaintext already deleted) → preflight fails → catch → exit 1
    var cse2 = _captureCtx();
    var rcse2 = await cli.main(["vault", "seal", "--data-dir", dir, "--passphrase", PP], cse2);
    check("vault seal (already sealed): exit 1", rcse2 === 1);
    check("vault seal (already sealed): message", /nothing to seal/.test(cse2.err()));

    // unseal with no passphrase → exit 2
    var cunp = _captureCtx();
    var rcunp = await cli.main(["vault", "unseal", "--data-dir", dir], cunp);
    check("vault unseal (no pass): exit 2", rcunp === 2);

    // unseal with the WRONG passphrase → unwrap rejects → catch → exit 1
    var cuw = _captureCtx();
    var rcuw = await cli.main(["vault", "unseal", "--data-dir", dir, "--passphrase", "totally-wrong-passphrase"], cuw);
    check("vault unseal (wrong pass): exit 1", rcuw === 1);
    check("vault unseal (wrong pass): message", /blamejs vault unseal:/.test(cuw.err()));

    // unseal → recreates plaintext vault.key, exit 0
    var cun = _captureCtx();
    var rcun = await cli.main(["vault", "unseal", "--data-dir", dir, "--passphrase", PP], cun);
    check("vault unseal: exit 0", rcun === 0);
    check("vault unseal: reports plaintext path", /unsealed: /.test(cun.out()));

    // re-seal keeping the plaintext (the --keep-plaintext branch), giving us a
    // sealed file for rotate.
    var cke = _captureCtx();
    var rcke = await cli.main(
      ["vault", "seal", "--data-dir", dir, "--passphrase", PP, "--keep-plaintext"], cke);
    check("vault seal --keep-plaintext: exit 0", rcke === 0);
    check("vault seal --keep-plaintext: kept plaintext", /kept plaintext vault\.key/.test(cke.out()));

    // rotate missing --new-passphrase → exit 2
    var crn = _captureCtx();
    var rcrn = await cli.main(["vault", "rotate", "--data-dir", dir, "--passphrase", PP], crn);
    check("vault rotate (no new-pass): exit 2", rcrn === 2);
    check("vault rotate (no new-pass): message", /both --passphrase \(old\) and --new-passphrase/.test(crn.err()));

    // rotate old→new → exit 0
    var cro = _captureCtx();
    var rcro = await cli.main(
      ["vault", "rotate", "--data-dir", dir, "--passphrase", PP, "--new-passphrase", NP], cro);
    check("vault rotate: exit 0", rcro === 0);
    check("vault rotate: reports rotated path", /rotated: /.test(cro.out()));

    // rotate with the WRONG old passphrase (sealed is now under NP) → the
    // unwrap in rotate rejects → catch → exit 1.
    var crw = _captureCtx();
    var rcrw = await cli.main(
      ["vault", "rotate", "--data-dir", dir, "--passphrase", PP, "--new-passphrase", "another-new-pass-999"], crw);
    check("vault rotate (wrong old pass): exit 1", rcrw === 1);
    check("vault rotate (wrong old pass): message", /blamejs vault rotate:/.test(crw.err()));
  } finally {
    b.vault._resetForTest();
    if (savedPass === undefined) delete process.env.BLAMEJS_VAULT_PASSPHRASE;
    else process.env.BLAMEJS_VAULT_PASSPHRASE = savedPass;
    _rm(dir);
  }
}

// ---------------------------------------------------------------------------
// password — the whole _runPassword body. No framework boot: it runs
// b.auth.password.policy(...).check(...) directly. --breach-check is NEVER
// exercised (it touches the network); every path here is offline.
// ---------------------------------------------------------------------------
async function sectionPassword() {
  // unknown subcommand → exit 2
  var cunk = _captureCtx();
  check("password unknown sub: exit 2", (await cli.main(["password", "frobnicate"], cunk)) === 2);
  check("password unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));

  // check with neither --plaintext nor --stdin → exit 2
  var cnop = _captureCtx();
  check("password check (no plaintext): exit 2", (await cli.main(["password", "check"], cnop)) === 2);
  check("password check (no plaintext): message", /--plaintext <s> or --stdin is required/.test(cnop.err()));

  // a strong passphrase → policy passes → "ok", exit 0
  var cok = _captureCtx();
  var rcok = await cli.main(
    ["password", "check", "--plaintext", "correct-horse-battery-staple-9273-Zx!"], cok);
  check("password check (strong): exit 0", rcok === 0);
  check("password check (strong): prints ok", /^ok/m.test(cok.out()));

  // a too-short password → policy rejects → REJECTED line, exit 1
  var crej = _captureCtx();
  var rcrej = await cli.main(["password", "check", "--plaintext", "x"], crej);
  check("password check (weak): exit 1", rcrej === 1);
  check("password check (weak): REJECTED line", /REJECTED: policy\/too-short/.test(crej.out()));

  // --json arm → machine-readable verdict; exit code still reflects ok
  var cjs = _captureCtx();
  var rcjs = await cli.main(
    ["password", "check", "--plaintext", "correct-horse-battery-staple-9273-Zx!", "--json"], cjs);
  check("password check --json (strong): exit 0", rcjs === 0);
  check("password check --json (strong): JSON body", /"ok":true/.test(cjs.out()));

  // --min-length + --max-length overrides + --email / --username context
  // flags all exercised.
  var cml = _captureCtx();
  var rcml = await cli.main(
    ["password", "check", "--plaintext", "abcd", "--min-length", "4", "--max-length", "128",
     "--email", "a@b.com", "--username", "alice"], cml);
  check("password check --min/max-length: exits 0/1 (ran policy)", rcml === 0 || rcml === 1);

  // an unknown --profile → policy() throws → "bad policy" exit 2
  var cbp = _captureCtx();
  var rcbp = await cli.main(
    ["password", "check", "--plaintext", "whatever-long-enough-string", "--profile", "no-such-profile"], cbp);
  check("password check bad profile: exit 2", rcbp === 2);
  check("password check bad profile: message", /bad policy:/.test(cbp.err()));
}

// ---------------------------------------------------------------------------
// file-type — unknown subcommand, allowlist match (non-json), allowlist
// rejection, and the plain (non-allowlist) detect success arms (text + json).
// ---------------------------------------------------------------------------
async function sectionFileTypeEdges() {
  var dir = _tmpDir("blamejs-cli-ft2");
  try {
    var pngFile = path.join(dir, "img.png");
    fs.writeFileSync(pngFile, Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), Buffer.alloc(20),
    ]));

    // unknown subcommand → exit 2
    var cunk = _captureCtx();
    check("file-type unknown sub: exit 2", (await cli.main(["file-type", "frobnicate"], cunk)) === 2);
    check("file-type unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));

    // allowlist match, NON-json → the human-readable mime/extension/category arm
    var cam = _captureCtx();
    var rcam = await cli.main(
      ["file-type", "detect", pngFile, "--allowlist", "image/png,application/pdf"], cam);
    check("file-type allowlist match (text): exit 0", rcam === 0);
    check("file-type allowlist match (text): mime line", /mime:\s+image\/png/.test(cam.out()));

    // allowlist that EXCLUDES the detected type → assertOneOf throws → exit 1
    var car = _captureCtx();
    var rcar = await cli.main(
      ["file-type", "detect", pngFile, "--allowlist", "application/pdf"], car);
    check("file-type allowlist reject: exit 1", rcar === 1);
    check("file-type allowlist reject: error message", /blamejs file-type detect:/.test(car.err()));

    // plain detect (no allowlist), NON-json → the mime/extension text arm
    var cpd = _captureCtx();
    var rcpd = await cli.main(["file-type", "detect", pngFile], cpd);
    check("file-type plain detect (text): exit 0", rcpd === 0);
    check("file-type plain detect (text): mime line", /mime:\s+image\/png/.test(cpd.out()));

    // plain detect (no allowlist), json → the json arm
    var cpj = _captureCtx();
    var rcpj = await cli.main(["file-type", "detect", pngFile, "--json"], cpj);
    check("file-type plain detect (json): exit 0", rcpj === 0);
    check("file-type plain detect (json): JSON body", /"mime":"image\/png"/.test(cpj.out()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// retention — unknown-sub + the arg-validation branches that fire BEFORE the
// framework boot (bad ttl / bad action / soft-delete-without-field) + the
// wrapped-boot-failure catch.
// ---------------------------------------------------------------------------
async function sectionRetentionEdges() {
  var dir = _tmpDir("blamejs-cli-ret2");
  try {
    var cunk = _captureCtx();
    check("retention unknown sub: exit 2", (await cli.main(["retention", "frobnicate"], cunk)) === 2);
    check("retention unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));

    // --ttl-ms 0 → non-positive → exit 2
    var cttl = _captureCtx();
    check("retention bad ttl: exit 2",
      (await cli.main(["retention", "preview", "--data-dir", dir, "--table", "t",
        "--age-field", "ts", "--ttl-ms", "0"], cttl)) === 2);
    check("retention bad ttl: message", /--ttl-ms must be a positive finite number/.test(cttl.err()));

    // unknown --action → exit 2
    var cact = _captureCtx();
    check("retention bad action: exit 2",
      (await cli.main(["retention", "preview", "--data-dir", dir, "--table", "t",
        "--age-field", "ts", "--ttl-ms", "1", "--action", "bogus"], cact)) === 2);
    check("retention bad action: message", /--action must be erase \/ delete \/ soft-delete/.test(cact.err()));

    // action=soft-delete without --soft-delete-field → exit 2
    var csd = _captureCtx();
    check("retention soft-delete no field: exit 2",
      (await cli.main(["retention", "preview", "--data-dir", dir, "--table", "t",
        "--age-field", "ts", "--ttl-ms", "1", "--action", "soft-delete"], csd)) === 2);
    check("retention soft-delete no field: message",
      /--soft-delete-field <col> required when --action=soft-delete/.test(csd.err()));

    // wrapped (default) vault-mode + empty env → boot fails → exit 1
    var cboot = _captureCtx();
    var rcboot = await cli.main(
      ["retention", "preview", "--data-dir", dir, "--table", "t",
       "--age-field", "ts", "--ttl-ms", "1"], cboot);
    check("retention wrapped-boot-fail: exit 1", rcboot === 1);
    check("retention wrapped-boot-fail: message", /boot failed/.test(cboot.err()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// erase — help, missing --confirm, wrapped-boot-failure, and the post-boot
// bad-identifier rejection (the safeTable-strip guard).
// ---------------------------------------------------------------------------
async function sectionEraseEdges() {
  var dir = _tmpDir("blamejs-cli-erase2");
  try {
    // erase --help → usage, exit 0 (the flags.help branch of the handler)
    var chelp = _captureCtx();
    var rchelp = await cli.main(["erase", "--help"], chelp);
    check("erase --help: exit 0", rchelp === 0);
    check("erase --help: usage", /Usage: blamejs erase/.test(chelp.out()));

    // missing --confirm (table + row present) → exit 2
    var cnc = _captureCtx();
    var rcnc = await cli.main(["erase", "--table", "users", "--row-id", "r-1"], cnc);
    check("erase no confirm: exit 2", rcnc === 2);
    check("erase no confirm: message", /--confirm is required/.test(cnc.err()));

    // default wrapped vault-mode + empty env → boot fails → exit 1
    var cboot = _captureCtx();
    var rcboot = await cli.main(
      ["erase", "--table", "users", "--row-id", "r-1", "--confirm", "--data-dir", dir], cboot);
    check("erase wrapped-boot-fail: exit 1", rcboot === 1);
    check("erase wrapped-boot-fail: message", /boot failed/.test(cboot.err()));

    // plaintext boot succeeds, then a table name with non-identifier chars is
    // rejected by the safeTable-strip guard → exit 2.
    var fresh = _tmpDir("blamejs-cli-erase2-id");
    try {
      var cid = _captureCtx();
      var rcid = await cli.main(
        ["erase", "--table", "bad-name!", "--row-id", "r-1", "--confirm",
         "--data-dir", fresh, "--vault-mode", "plaintext"], cid);
      check("erase bad-identifier table: exit 2", rcid === 2);
      check("erase bad-identifier table: message", /--table must be a valid identifier/.test(cid.err()));
    } finally { _rm(fresh); }
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// api-key — bare / unknown-sub / missing-data-dir dispatch + the wrapped-boot
// failure catch.
// ---------------------------------------------------------------------------
async function sectionApiKeyEdges() {
  var dir = _tmpDir("blamejs-cli-apikey2");
  try {
    var cbare = _captureCtx();
    check("api-key bare: exit 2", (await cli.main(["api-key"], cbare)) === 2);
    check("api-key bare: usage", /Usage: blamejs api-key/.test(cbare.err()));

    var cunk = _captureCtx();
    check("api-key unknown sub: exit 2", (await cli.main(["api-key", "frobnicate"], cunk)) === 2);
    check("api-key unknown sub: names sub", /unknown subcommand 'frobnicate'/.test(cunk.err()));

    var cnodir = _captureCtx();
    check("api-key no data-dir: exit 2", (await cli.main(["api-key", "issue"], cnodir)) === 2);
    check("api-key no data-dir: message", /--data-dir <path> is required/.test(cnodir.err()));

    // data-dir + namespace present, default wrapped vault-mode, empty env →
    // bootApp throws → the catch reports "boot failed" (exit 1).
    var cboot = _captureCtx();
    var rcboot = await cli.main(
      ["api-key", "issue", "--data-dir", dir, "--namespace", "api",
       "--owner-id", "x", "--scopes", "a:read"], cboot);
    check("api-key wrapped-boot-fail: exit 1", rcboot === 1);
    check("api-key wrapped-boot-fail: message", /boot failed/.test(cboot.err()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// booted raw-table paths: retention run (json delete + non-json soft-delete
// with legal-hold) and erase (row-not-found + no-sealed-columns). The CLI
// boots its OWN app per invocation, so the table is created out-of-band with a
// raw node:sqlite handle after a first boot materialises the db file.
// ---------------------------------------------------------------------------
async function sectionBootedRawTable() {
  var dir = _tmpDir("blamejs-cli-rawtbl");
  try {
    // First plaintext boot (against a missing table) materialises blamejs.db.
    await cli.main(
      ["retention", "preview", "--data-dir", dir, "--vault-mode", "plaintext",
       "--table", "seed_missing", "--age-field", "ts", "--ttl-ms", "1", "--action", "delete"],
      _captureCtx());
    var dbFile = path.join(dir, "blamejs.db");
    check("rawtbl: db file materialised", fs.existsSync(dbFile));

    // Create a plain table with one old row + a soft-delete table with a
    // legal-hold row, via a raw handle while no app holds the db.
    var h = new sqlite.DatabaseSync(dbFile);
    h.exec("CREATE TABLE ret_del (_id TEXT PRIMARY KEY, ts INTEGER)");
    h.prepare("INSERT INTO ret_del (_id, ts) VALUES (?, ?)").run("d-old", 1);
    h.exec("CREATE TABLE ret_soft (_id TEXT PRIMARY KEY, ts INTEGER, deletedAt INTEGER, hold INTEGER)");
    var ins = h.prepare("INSERT INTO ret_soft (_id, ts, deletedAt, hold) VALUES (?, ?, ?, ?)");
    ins.run("s-1", 1, null, null);
    ins.run("s-2", 1, null, 1);
    h.exec("CREATE TABLE er_plain (_id TEXT PRIMARY KEY, ts INTEGER)");
    h.prepare("INSERT INTO er_plain (_id, ts) VALUES (?, ?)").run("er-1", 5);
    h.close();

    // retention run --json against the delete table → success, json summary arm
    var cj = _captureCtx();
    var rcj = await cli.main(
      ["retention", "run", "--data-dir", dir, "--vault-mode", "plaintext",
       "--table", "ret_del", "--age-field", "ts", "--ttl-ms", "1", "--action", "delete", "--json"], cj);
    check("retention run (json delete): exit 0", rcj === 0);
    check("retention run (json delete): json summary", /"processed":\s*1/.test(cj.out()));

    // retention run non-json soft-delete + legal-hold → the text summary arm,
    // the soft-delete-field / legal-hold-field ruleSpec wiring, and a honored
    // legal hold.
    var cs = _captureCtx();
    var rcs = await cli.main(
      ["retention", "run", "--data-dir", dir, "--vault-mode", "plaintext",
       "--table", "ret_soft", "--age-field", "ts", "--ttl-ms", "1", "--action", "soft-delete",
       "--soft-delete-field", "deletedAt", "--legal-hold-field", "hold"], cs);
    check("retention run (soft-delete): exit 0", rcs === 0);
    check("retention run (soft-delete): text summary", /processed:1/.test(cs.out()));
    check("retention run (soft-delete): honored legal hold", /legalHoldsHonored: 1/.test(cs.out()));

    // erase against an EXISTING table but a missing row id → the "no row" branch
    var cnr = _captureCtx();
    var rcnr = await cli.main(
      ["erase", "--data-dir", dir, "--vault-mode", "plaintext",
       "--table", "er_plain", "--row-id", "does-not-exist", "--confirm"], cnr);
    check("erase (row not found): exit 1", rcnr === 1);
    check("erase (row not found): message", /no row with _id=/.test(cnr.err()));

    // erase a REAL row in a table with no sealed columns / derived hashes → the
    // "nothing sealed to erase" guard.
    var cns = _captureCtx();
    var rcns = await cli.main(
      ["erase", "--data-dir", dir, "--vault-mode", "plaintext",
       "--table", "er_plain", "--row-id", "er-1", "--confirm"], cns);
    check("erase (no sealed columns): exit 1", rcns === 1);
    check("erase (no sealed columns): message", /has no sealed columns or derived hashes/.test(cns.err()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// top-level dispatch — an unknown command prints the "unknown command" error
// plus the top usage, exit 2.
// ---------------------------------------------------------------------------
async function sectionTopUnknownCommand() {
  var c = _captureCtx();
  var rc = await cli.main(["totally-unknown-command"], c);
  check("unknown top-level command: exit 2", rc === 2);
  check("unknown top-level command: names it", /unknown command 'totally-unknown-command'/.test(c.err()));
  check("unknown top-level command: prints top usage", /blamejs <command>/.test(c.out()));
}

// ---------------------------------------------------------------------------
// top-level dispatch — the option-default fallbacks in main(), the non-array
// argv guard, the `--version` (long) + `version` command paths, and the
// per-command `help <topic>` fan-out block (one line per subcommand USAGE).
// ---------------------------------------------------------------------------
async function sectionTopLevelDispatch2() {
  // main() with a NON-ARRAY (undefined) argv AND no opts object at all.
  // Exercises `if (!Array.isArray(argv)) argv = []`, every `opts.<x> ||
  // process.<x>` default, and the `cmd === undefined` top-help early return.
  // Output goes to the real process.stdout (no ctx supplied) — a single
  // usage block, harmless to the check tally.
  var rcUndef = await cli.main(undefined);
  check("main(undefined) → exit 0 (non-array guard + opts defaults + cmd-undefined)", rcUndef === 0);

  // `--version` (long flag) → the LEFT operand of `args.flags.version ||
  // args.flags.v`; only `-v` (the right operand) was covered before.
  var cVer = _captureCtx();
  var rcVer = await cli.main(["--version"], cVer);
  check("--version long flag → exit 0", rcVer === 0);
  check("--version long flag → prints version", /\d+\.\d+\.\d+/.test(cVer.out()));

  // `version` positional command → the dedicated `cmd === "version"` branch
  // (distinct from the top-level --version/-v flag handling above).
  var cVerCmd = _captureCtx();
  var rcVerCmd = await cli.main(["version"], cVerCmd);
  check("version command → exit 0", rcVerCmd === 0);
  check("version command → prints version", /\d+\.\d+\.\d+/.test(cVerCmd.out()));

  // `help <topic>` for every reporter-/writeLine-backed subcommand → the
  // per-topic dispatch block (each prints that command's USAGE, exit 0).
  var topics = [
    ["dev",          /Usage: blamejs dev/],
    ["api-snapshot", /Usage: blamejs api-snapshot/],
    ["api-key",      /Usage: blamejs api-key/],
    ["audit",        /Usage: blamejs audit/],
    ["backup",       /Usage: blamejs backup/],
    ["restore",      /Usage: blamejs restore/],
    ["mtls",         /Usage: blamejs mtls/],
    ["vault",        /Usage: blamejs vault/],
    ["security",     /Usage: blamejs security/],
    ["config-drift", /Usage: blamejs config-drift/],
    ["file-type",    /Usage: blamejs file-type/],
    ["password",     /Usage: blamejs password/],
    ["retention",    /Usage: blamejs retention/],
  ];
  for (var i = 0; i < topics.length; i++) {
    var ctx = _captureCtx();
    var rc = await cli.main(["help", topics[i][0]], ctx);
    check("help " + topics[i][0] + " → exit 0", rc === 0);
    check("help " + topics[i][0] + " → prints its USAGE", topics[i][1].test(ctx.out()));
  }
}

// ---------------------------------------------------------------------------
// migrate — default --dir (omitted) + adversarial --steps values (fractional /
// non-numeric). The fractional guard mirrors the sibling `verify-chain
// --max-rows 2.5` refusal: the message promises "a positive integer", so 2.5
// must be refused at the entry point, never floored-and-run.
// ---------------------------------------------------------------------------
async function sectionMigrateMore() {
  var dir = _tmpDir("blamejs-cli-migrate-more");
  try {
    var dbPath = path.join(dir, "mig.db");
    // status with --db but NO --dir → the `args.flags.dir || DEFAULT_MIG_DIR`
    // default arm (resolves ./migrations relative to cwd). Whether that dir
    // exists or not, dispatch gets past arg-validation into the runner.
    var cdef = _captureCtx();
    var rcdef = await cli.main(["migrate", "status", "--db", dbPath], cdef);
    check("migrate status (default --dir): not a bad-invocation", rcdef !== 2);

    // --steps 2.5 → fractional → positive-integer guard → exit 2. Before this,
    // migrate only exercised --steps 0 (the `< 1` clause); the non-integer
    // clause (`Math.floor(steps) !== steps`) went untested for migrate.
    var cfrac = _captureCtx();
    var rcfrac = await cli.main(["migrate", "down", "--db", dbPath, "--steps", "2.5"], cfrac);
    check("migrate down --steps 2.5 → exit 2", rcfrac === 2);
    check("migrate down --steps 2.5 → message", /--steps must be a positive integer/.test(cfrac.err()));

    // --steps not-a-number → NaN → !Number.isFinite clause → exit 2.
    var cnan = _captureCtx();
    var rcnan = await cli.main(["migrate", "down", "--db", dbPath, "--steps", "not-a-number"], cnan);
    check("migrate down --steps non-numeric → exit 2", rcnan === 2);
    check("migrate down --steps non-numeric → message", /--steps must be a positive integer/.test(cnan.err()));
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// api-key — the post-boot REQUIRED-flag guards for revoke / list / rotate /
// verify (each fires only after a successful boot, mirroring the issue guards
// already covered) + rotate WITH --grace-ms (the Number(graceMs) arm) + an
// adversarial non-numeric --expires-ms (downstream validation rejects it).
// ---------------------------------------------------------------------------
async function sectionApiKeyMore() {
  var dataDir = _tmpDir("blamejs-cli-apikey3");
  try {
    var base = ["--data-dir", dataDir, "--vault-mode", "plaintext", "--namespace", "api"];

    // revoke with no --id (post-boot) → exit 2
    var crv = _captureCtx();
    var rcrv = await cli.main(["api-key", "revoke"].concat(base), crv);
    check("apikey revoke no --id (post-boot) → exit 2", rcrv === 2);
    check("apikey revoke no --id → message", /--id <idHex> is required/.test(crv.err()));

    // list with no --owner-id (post-boot) → exit 2
    var cls = _captureCtx();
    var rcls = await cli.main(["api-key", "list"].concat(base), cls);
    check("apikey list no --owner-id (post-boot) → exit 2", rcls === 2);
    check("apikey list no --owner-id → message", /--owner-id <id> is required/.test(cls.err()));

    // rotate with no --id (post-boot) → exit 2
    var crt = _captureCtx();
    var rcrt = await cli.main(["api-key", "rotate"].concat(base), crt);
    check("apikey rotate no --id (post-boot) → exit 2", rcrt === 2);
    check("apikey rotate no --id → message", /--id <idHex> is required/.test(crt.err()));

    // verify with no --token (post-boot) → exit 2
    var cvt = _captureCtx();
    var rcvt = await cli.main(["api-key", "verify"].concat(base), cvt);
    check("apikey verify no --token (post-boot) → exit 2", rcvt === 2);
    check("apikey verify no --token → message", /--token <key> is required/.test(cvt.err()));

    // issue a key, then rotate WITH --grace-ms → the `Number(graceMs)` arm of
    // the gracePeriodMs ternary (the default `: 0` arm is covered elsewhere).
    var ci = _captureCtx();
    var rci = await cli.main(["api-key", "issue"].concat(base).concat(
      ["--owner-id", "gm", "--scopes", "a:read"]), ci);
    check("apikey issue (for grace rotate): exit 0", rci === 0);
    var idMatch = ci.out().match(/^id:\s+([a-f0-9]+)/m);
    if (idMatch) {
      var cgr = _captureCtx();
      var rcgr = await cli.main(["api-key", "rotate"].concat(base).concat(
        ["--id", idMatch[1], "--grace-ms", "60000"]), cgr);
      check("apikey rotate --grace-ms → exit 0", rcgr === 0);
      check("apikey rotate --grace-ms → prints new key", /key \(new\):/.test(cgr.out()));
    }

    // issue a key then revoke it by id → the revoke SUCCESS arm
    // (`revoked ? report.ok("revoked: ...") : ...`); the no-op/false arm is
    // covered by sectionBootedApiKey.
    var ck = _captureCtx();
    await cli.main(["api-key", "issue"].concat(base).concat(
      ["--owner-id", "rv", "--scopes", "a:read"]), ck);
    var rvId = ck.out().match(/^id:\s+([a-f0-9]+)/m);
    if (rvId) {
      var crvk = _captureCtx();
      var rcrvk = await cli.main(["api-key", "revoke"].concat(base).concat(["--id", rvId[1]]), crvk);
      check("apikey revoke (real key) → exit 0", rcrvk === 0);
      check("apikey revoke (real key) → revoked message", /revoked: /.test(crvk.out()));
    }

    // adversarial: --expires-ms with a non-numeric value → Number() → NaN →
    // apiKey.issue's downstream numeric validation rejects (exit 1, not a
    // silently-stored NaN expiry). Drives the real consumer reject path.
    var cbad = _captureCtx();
    var rcbad = await cli.main(["api-key", "issue"].concat(base).concat(
      ["--owner-id", "nanx", "--scopes", "a:read", "--expires-ms", "not-ms"]), cbad);
    check("apikey issue --expires-ms non-numeric → rejected (exit 1)", rcbad === 1);
    check("apikey issue --expires-ms non-numeric → validation message",
      /expiresAt must be a non-negative finite number/.test(cbad.err()));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// security — assert WITHOUT --no-vault / --no-db-at-rest / --no-audit-signing
// negations toggled off for two of the three postures, so the default posture
// arms ("wrapped" / "encrypted") are chosen, plus --no-vault selected so the
// `false` (skip) arm of the vault ternary is taken. The plaintext boot fails
// the asserted postures → FAIL summary, exit 1.
// ---------------------------------------------------------------------------
async function sectionSecurityMore() {
  var dataDir = _tmpDir("blamejs-cli-sec3");
  try {
    var ctx = _captureCtx();
    var rc = await cli.main(
      ["security", "assert", "--data-dir", dataDir, "--vault-mode", "plaintext",
       "--no-vault", "--no-ntp-strict"], ctx);
    // --no-vault → vault:false (skip); dbAtRest defaults to "encrypted" and
    // auditSigning to "wrapped" (both asserted against the plaintext boot) →
    // the assertion fails → exit 1 with a FAIL summary.
    check("security assert (default postures) → exit 1", rc === 1);
    check("security assert (default postures) → FAIL summary", /FAIL:/.test(ctx.out()));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// misc cheap arg-guards that fire before any boot:
//   file-type detect with NO file positional  → "file path is required"
//   erase with no --table / no --row-id        → the two ordered guards
//   retention with no --table / no --age-field → the two ordered guards
//   vault status with NO --data-dir            → the "./data" default arm
//   password check --json on a WEAK plaintext  → the json arm's `? 0 : 1`
// ---------------------------------------------------------------------------
async function sectionCheapGuards() {
  // file-type detect with no positional file → exit 2
  var cft = _captureCtx();
  var rcft = await cli.main(["file-type", "detect"], cft);
  check("file-type detect (no file) → exit 2", rcft === 2);
  check("file-type detect (no file) → message", /file path is required/.test(cft.err()));

  // erase with nothing → the --table guard fires first (before --row-id) → 2
  var cet = _captureCtx();
  var rcet = await cli.main(["erase"], cet);
  check("erase (no --table) → exit 2", rcet === 2);
  check("erase (no --table) → message", /--table <name> is required/.test(cet.err()));

  // erase --table present, no --row-id → the --row-id guard → 2
  var cer = _captureCtx();
  var rcer = await cli.main(["erase", "--table", "t"], cer);
  check("erase (no --row-id) → exit 2", rcer === 2);
  check("erase (no --row-id) → message", /--row-id <id> is required/.test(cer.err()));

  // retention --data-dir present, no --table → the --table guard → 2
  var crt = _captureCtx();
  var rcrt = await cli.main(["retention", "preview", "--data-dir", "/tmp/x"], crt);
  check("retention (no --table) → exit 2", rcrt === 2);
  check("retention (no --table) → message", /--table <name> is required/.test(crt.err()));

  // retention --table present, no --age-field → the --age-field guard → 2
  var cra = _captureCtx();
  var rcra = await cli.main(["retention", "preview", "--data-dir", "/tmp/x", "--table", "t"], cra);
  check("retention (no --age-field) → exit 2", rcra === 2);
  check("retention (no --age-field) → message", /--age-field <col> is required/.test(cra.err()));

  // vault status with NO --data-dir → the `args.flags["data-dir"] || "./data"`
  // default arm is resolved before the status block runs (covers that arm
  // regardless of whether ./data exists in the cwd).
  var cvd = _captureCtx();
  var rcvd = await cli.main(["vault", "status"], cvd);
  check("vault status (default ./data) → resolved default, no throw", rcvd === 0 || rcvd === 1);

  // BUG (fixed in cli.js): `vault status` against a NON-EXISTENT data-dir must
  // surface the standard clean reporter error (exit 1) — NOT reject main()
  // with an uncaught VaultPassphraseError (which the bin shim would render as
  // a stack trace). preflightSealable/preflightUnsealable throw when the dir
  // is absent; the status block now catches it exactly like seal/unseal/rotate.
  var missingDir = path.join(os.tmpdir(), "blamejs-cli-vault-nonexistent-" + Date.now());
  var cvm = _captureCtx();
  var threwVaultStatus = false;
  var rcvm;
  try { rcvm = await cli.main(["vault", "status", "--data-dir", missingDir], cvm); }
  catch (_e) { threwVaultStatus = true; }
  check("vault status (missing data-dir) → never rejects main()", threwVaultStatus === false);
  check("vault status (missing data-dir) → clean exit 1", rcvm === 1);
  check("vault status (missing data-dir) → data-dir-does-not-exist message",
    /does not exist/.test(cvm.err()));

  // password check --json on a WEAK plaintext → the json arm returns
  // `verdict.ok ? 0 : 1`; the strong-json case (0) was covered, this is the 1.
  var cpj = _captureCtx();
  var rcpj = await cli.main(["password", "check", "--plaintext", "x", "--json"], cpj);
  check("password check --json (weak) → exit 1", rcpj === 1);
  check("password check --json (weak) → JSON ok:false", /"ok":false/.test(cpj.out()));
}

// ---------------------------------------------------------------------------
// mtls — post-boot required-flag guards (issue / issue-p12 missing --subject /
// --password, checked BEFORE cert generation) + a --sealed-mode disabled init
// (the plaintext-key-on-disk path, distinct from the default "required" seal).
// ---------------------------------------------------------------------------
async function sectionMtlsMore() {
  var dataDir = _tmpDir("blamejs-cli-mtls3");
  try {
    var base = ["--data-dir", dataDir, "--vault-mode", "plaintext"];

    // issue with no --subject (post-boot) → exit 2
    var cis = _captureCtx();
    var rcis = await cli.main(["mtls", "issue"].concat(base), cis);
    check("mtls issue no --subject (post-boot) → exit 2", rcis === 2);
    check("mtls issue no --subject → message", /--subject <CN> is required/.test(cis.err()));

    // issue-p12 with no --subject → exit 2
    var cps = _captureCtx();
    var rcps = await cli.main(["mtls", "issue-p12"].concat(base), cps);
    check("mtls issue-p12 no --subject → exit 2", rcps === 2);
    check("mtls issue-p12 no --subject → message", /--subject <CN> is required/.test(cps.err()));

    // issue-p12 with --subject but no --password → exit 2
    var cpp = _captureCtx();
    var rcpp = await cli.main(["mtls", "issue-p12"].concat(base).concat(["--subject", "cn"]), cpp);
    check("mtls issue-p12 no --password → exit 2", rcpp === 2);
    check("mtls issue-p12 no --password → message", /--password <pkcs12-passphrase> is required/.test(cpp.err()));

    // init with --sealed-mode disabled → the CA key is written PLAINTEXT to
    // disk (ca.paths.caKey), the non-default arm of the init key-path report.
    var cin = _captureCtx();
    var rcin = await cli.main(["mtls", "init"].concat(base).concat(["--sealed-mode", "disabled"]), cin);
    check("mtls init --sealed-mode disabled → exit 0", rcin === 0);
    check("mtls init --sealed-mode disabled → reports plaintext ca-key", /ca-key:\s+\S+/.test(cin.out()));

    // status against the disabled-mode CA → exercises the exists-true + paths
    // block once more under the plaintext-key layout.
    var cst = _captureCtx();
    var rcst = await cli.main(["mtls", "status"].concat(base).concat(["--sealed-mode", "disabled"]), cst);
    check("mtls status (disabled CA) → exit 0", rcst === 0);
    check("mtls status (disabled CA) → CA exists yes", /CA exists:\s+yes/.test(cst.out()));
  } finally { _rm(dataDir); }
}

// ---------------------------------------------------------------------------
// restore — the success-side list / list-rollbacks loop bodies (which only run
// when storage / rollback-root actually contain entries) + an apply that gets
// PAST the max-pulled-* numeric gates with valid values and a --rollback-root,
// building the restore engine before run() rejects on the absent bundle.
// The storage + rollback fixtures are crafted directly on disk in the exact
// shapes b.backup.diskStorage.listBundles + b.restoreRollback.list read
// (a timestamp+suffix bundle dir; a non-"discarded-" rollback point dir).
// ---------------------------------------------------------------------------
async function sectionRestoreMore() {
  var dir = _tmpDir("blamejs-cli-restore3");
  try {
    // --- list with a bundle present → the "bundles in <root>: N" + per-bundle
    // row loop (only reached when listBundles() returns > 0). ---
    var store = path.join(dir, "store");
    var bundleId = "2026-05-24T15-00-00-000Z-aabb1100"; // valid timestamp+suffix
    fs.mkdirSync(path.join(store, bundleId), { recursive: true });
    fs.writeFileSync(path.join(store, bundleId, "manifest.json"), "{}");
    var cl = _captureCtx();
    var rcl = await cli.main(["restore", "list", "--storage-root", store], cl);
    check("restore list (populated) → exit 0", rcl === 0);
    check("restore list (populated) → bundle-count header", /bundles in .*: 1/.test(cl.out()));
    check("restore list (populated) → lists the bundle id", new RegExp(bundleId).test(cl.out()));

    // --- list-rollbacks with a point present → the "rollback points at ...: N"
    // + per-point row loop (only reached when list() returns > 0). ---
    var dd = path.join(dir, "dd");
    fs.mkdirSync(dd, { recursive: true });
    var rbRoot = path.join(dir, "rbroot");
    fs.mkdirSync(path.join(rbRoot, "point-0001"), { recursive: true });
    // A sibling <point>.marker.json carries the operator metadata the listing
    // annotates each point with (bundleId / reason on marker.operator, swappedAt
    // top-level) -- the row previously read a non-existent recordedAt/bundleId.
    fs.writeFileSync(path.join(rbRoot, "point-0001.marker.json"),
      JSON.stringify({ swappedAt: "2026-05-24T15:00:00.000Z", operator: { bundleId: "bk-test-123", reason: "unit-test" } }));
    var clr = _captureCtx();
    var rclr = await cli.main(
      ["restore", "list-rollbacks", "--data-dir", dd, "--rollback-root", rbRoot], clr);
    check("restore list-rollbacks (populated) → exit 0", rclr === 0);
    check("restore list-rollbacks (populated) → point-count header", /rollback points at .*: 1/.test(clr.out()));
    check("restore list-rollbacks (populated) → lists the point", /point-0001/.test(clr.out()));
    check("restore list-rollbacks (populated) → renders swappedAt from the marker",
      /swappedAt=2026-05-24T15:00:00\.000Z/.test(clr.out()));
    check("restore list-rollbacks (populated) → renders bundleId from marker.operator",
      /bundleId=bk-test-123/.test(clr.out()));

    // --- apply past the numeric gates: valid --max-pulled-bytes / -files +
    // --rollback-root build the restore engine; run() then rejects because the
    // bundle can't be pulled → the catch returns non-zero (exit 1). This
    // covers the Number(maxBytes)/Number(maxFiles) opt-mapping arms and the
    // rollback-root resolution arm, distinct from the earlier bad-value gates. ---
    var ca = _captureCtx();
    var rca = await cli.main(
      ["restore", "apply", "--data-dir", path.join(dir, "dd2"),
       "--bundle", path.join(store, bundleId), "--passphrase", "p",
       "--max-pulled-bytes", "1048576", "--max-pulled-files", "100",
       "--rollback-root", path.join(dir, "rb2")], ca);
    check("restore apply (valid gates, unpullable bundle) → exit 1", rca === 1);
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// audit — drive each of archive / export / verify-bundle / purge with ALL of
// its required flags present, so dispatch gets PAST the arg-validation returns
// and into the auditTools.* call (and its surrounding try/catch). Against a
// fresh process with no live audit chain the call fails and the catch reports
// it — but the point is coverage of the operation body + its error path, which
// the existing tests (each omitting one required flag) never reach. Assert
// only that we got past validation (exit != 2), robust to whether an ambient
// booted db makes the call succeed or fail.
// ---------------------------------------------------------------------------
async function sectionAuditOps() {
  var dir = _tmpDir("blamejs-cli-auditops");
  try {
    // archive: passphrase + out + before all present → into auditTools.archive
    var ca = _captureCtx();
    var rca = await cli.main(
      ["audit", "archive", "--passphrase", "p", "--out", path.join(dir, "arc-out"),
       "--before", "2000-01-01"], ca);
    check("audit archive (all flags) → past validation (exit != 2)", rca !== 2);

    // export: passphrase + out + a range flag present → into exportSlice
    var ce = _captureCtx();
    var rce = await cli.main(
      ["audit", "export", "--passphrase", "p", "--out", path.join(dir, "exp-out"),
       "--from", "2000-01-01"], ce);
    check("audit export (all flags) → past validation (exit != 2)", rce !== 2);

    // verify-bundle: passphrase + in present → into verifyBundle
    var cv = _captureCtx();
    var rcv = await cli.main(
      ["audit", "verify-bundle", "--passphrase", "p", "--in", path.join(dir, "no-bundle")], cv);
    check("audit verify-bundle (all flags) → past validation (exit != 2)", rcv !== 2);

    // purge: passphrase + archive + confirm present → into purge
    var cp = _captureCtx();
    var rcp = await cli.main(
      ["audit", "purge", "--passphrase", "p", "--archive", path.join(dir, "no-arc"), "--confirm"], cp);
    check("audit purge (all flags) → past validation (exit != 2)", rcp !== 2);
  } finally { _rm(dir); }
}

// ---------------------------------------------------------------------------
// retention — a booted PREVIEW (dry-run) with non-JSON text output against a
// real table, plus an explicit valid --batch-size, so the "DRY-RUN " summary
// prefix arm and the Number(batchSize) opt arm are both exercised (the JSON
// arm + the non-preview text arm are covered by sectionBootedRawTable).
// ---------------------------------------------------------------------------
async function sectionRetentionPreviewText() {
  var dir = _tmpDir("blamejs-cli-ret3");
  try {
    // First plaintext boot (missing table) materialises blamejs.db.
    await cli.main(
      ["retention", "preview", "--data-dir", dir, "--vault-mode", "plaintext",
       "--table", "seed_missing", "--age-field", "ts", "--ttl-ms", "1", "--action", "delete"],
      _captureCtx());
    var dbFile = path.join(dir, "blamejs.db");
    check("ret-preview-text: db file materialised", fs.existsSync(dbFile));

    var h = new sqlite.DatabaseSync(dbFile);
    h.exec("CREATE TABLE ret_prev (_id TEXT PRIMARY KEY, ts INTEGER)");
    h.prepare("INSERT INTO ret_prev (_id, ts) VALUES (?, ?)").run("p-old", 1);
    h.close();

    // preview (dry-run) non-JSON + explicit --batch-size → DRY-RUN text arm +
    // Number(batchSize) arm.
    var cp = _captureCtx();
    var rcp = await cli.main(
      ["retention", "preview", "--data-dir", dir, "--vault-mode", "plaintext",
       "--table", "ret_prev", "--age-field", "ts", "--ttl-ms", "1", "--action", "delete",
       "--batch-size", "250"], cp);
    check("retention preview (text): exit 0", rcp === 0);
    check("retention preview (text): DRY-RUN prefix", /DRY-RUN rule:/.test(cp.out()));
  } finally { _rm(dir); }
}

async function run() {
  var dir = _tmpDir("blamejs-cli");
  try {
    // =====================================================================
    // seed — arg validation
    // =====================================================================

    // bare `seed` (no subcommand) → usage on stderr, exit 2
    var cBare = _captureCtx();
    var rcBare = await cli.main(["seed"], cBare);
    check("seed: bare → exit 2",                rcBare === 2);
    check("seed: bare → usage on stderr",       /Usage: blamejs seed/.test(cBare.err()));

    // `seed help` → usage on stdout, exit 0
    var cHelp = _captureCtx();
    var rcHelp = await cli.main(["seed", "help"], cHelp);
    check("seed help: exit 0",                  rcHelp === 0);
    check("seed help: usage on stdout",         /Usage: blamejs seed/.test(cHelp.out()));
    check("seed help: lists run + status",      /\brun\b/.test(cHelp.out()) && /\bstatus\b/.test(cHelp.out()));

    // `help seed` (top-level help dispatch → SEED_USAGE)
    var cTopHelpSeed = _captureCtx();
    var rcTopHelpSeed = await cli.main(["help", "seed"], cTopHelpSeed);
    check("help seed: exit 0",                  rcTopHelpSeed === 0);
    check("help seed: prints SEED_USAGE",       /Usage: blamejs seed/.test(cTopHelpSeed.out()));

    // unknown subcommand → exit 2 + usage
    var cUnk = _captureCtx();
    var rcUnk = await cli.main(["seed", "frobnicate"], cUnk);
    check("seed unknown sub: exit 2",           rcUnk === 2);
    check("seed unknown sub: names the sub",    /unknown subcommand 'frobnicate'/.test(cUnk.err()));

    // run without --db → exit 2
    var cNoDb = _captureCtx();
    var rcNoDb = await cli.main(["seed", "run"], cNoDb);
    check("seed run: missing --db → exit 2",    rcNoDb === 2);
    check("seed run: missing --db message",     /--db <path> is required/.test(cNoDb.err()));

    // --db present but bare (boolean flag, no value) → treated as missing
    var cDbBool = _captureCtx();
    var rcDbBool = await cli.main(["seed", "run", "--db"], cDbBool);
    check("seed run: --db with no value → exit 2", rcDbBool === 2);
    check("seed run: --db no value message",       /--db <path> is required/.test(cDbBool.err()));

    // --db present, --env missing → exit 2
    var dbPath = path.join(dir, "seed.db");
    var cNoEnv = _captureCtx();
    var rcNoEnv = await cli.main(["seed", "status", "--db", dbPath], cNoEnv);
    check("seed status: missing --env → exit 2", rcNoEnv === 2);
    check("seed status: missing --env message",  /--env <name> is required/.test(cNoEnv.err()));

    // bad db path (parent dir doesn't exist) → cannot open db, exit 1
    var cBadDb = _captureCtx();
    var rcBadDb = await cli.main(
      ["seed", "status", "--db", path.join(dir, "no-such-dir", "x.db"), "--env", "dev"],
      cBadDb);
    check("seed status: unopenable db → exit 1", rcBadDb === 1);
    check("seed status: cannot-open message",    /cannot open db/.test(cBadDb.err()));

    // =====================================================================
    // seed — status happy path against a local sqlite file + empty dir
    // =====================================================================
    var seedersDir = path.join(dir, "seeders-empty");
    var cStatus = _captureCtx();
    var rcStatus = await cli.main(
      ["seed", "status", "--db", dbPath, "--env", "dev", "--dir", seedersDir],
      cStatus);
    check("seed status: empty dir → exit 0",     rcStatus === 0);
    check("seed status: prints env line",        /env: dev/.test(cStatus.out()));
    check("seed status: 0 applied of 0 total",   /applied: 0 \/ 0/.test(cStatus.out()));
    check("seed status: 0 pending",              /pending: 0/.test(cStatus.out()));

    // =====================================================================
    // dev — --grace-ms numeric validation (returns before spawning a child)
    // =====================================================================
    var cGraceNeg = _captureCtx();
    var rcGraceNeg = await cli.main(
      ["dev", "--command", "node", "--grace-ms", "-5"], cGraceNeg);
    check("dev --grace-ms negative → exit 2",    rcGraceNeg === 2);
    check("dev --grace-ms negative message",     /--grace-ms must be a non-negative number/.test(cGraceNeg.err()));

    var cGraceNaN = _captureCtx();
    var rcGraceNaN = await cli.main(
      ["dev", "--command", "node", "--grace-ms", "not-a-number"], cGraceNaN);
    check("dev --grace-ms non-numeric → exit 2", rcGraceNaN === 2);
    check("dev --grace-ms non-numeric message",  /--grace-ms must be a non-negative number/.test(cGraceNaN.err()));

    // missing --command still exits 2 (guards the `dev` entry independent
    // of the grace-ms path above)
    var cDevNoCmd = _captureCtx();
    var rcDevNoCmd = await cli.main(["dev"], cDevNoCmd);
    check("dev: missing --command → exit 2",     rcDevNoCmd === 2);
    check("dev: missing --command message",      /--command <cmd> is required/.test(cDevNoCmd.err()));

    // =====================================================================
    // dev — --ignore pattern refusal takes the standard exit-2 + stderr
    // path, never rejects main(). An over-length pattern, a ReDoS-shape
    // pattern guardRegex refuses, and a pattern RegExp() can't compile are
    // all operator-input validation failures: they must return exit 2 like
    // every other dev validation, not reject the awaited promise (which the
    // bin shim would surface as a stack-trace + exit 1).
    // =====================================================================
    async function _devIgnore(pattern) {
      var c = _captureCtx();
      var rejected = false;
      var rc;
      try {
        rc = await cli.main(["dev", "--command", "node", "--ignore", pattern], c);
      } catch (_e) {
        rejected = true;
      }
      return { rc: rc, rejected: rejected, err: c.err() };
    }

    var igLong = await _devIgnore("a".repeat(300));
    check("dev --ignore over-length → never rejects main()", igLong.rejected === false);
    check("dev --ignore over-length → exit 2",               igLong.rc === 2);
    check("dev --ignore over-length message",                /exceeds max length/.test(igLong.err));

    var igReDoS = await _devIgnore("(a+)+$");
    check("dev --ignore ReDoS-shape → never rejects main()", igReDoS.rejected === false);
    check("dev --ignore ReDoS-shape → exit 2",               igReDoS.rc === 2);
    check("dev --ignore ReDoS-shape message",                /refused by guardRegex/.test(igReDoS.err));

    var igBadRe = await _devIgnore("(");
    check("dev --ignore uncompilable → never rejects main()", igBadRe.rejected === false);
    check("dev --ignore uncompilable → exit 2",               igBadRe.rc === 2);
    check("dev --ignore uncompilable message",                /--ignore pattern/.test(igBadRe.err));

    // =====================================================================
    // api-snapshot — operator-supplied --module
    // =====================================================================

    // capture from a non-existent module → cannot load, exit 1
    var cModBad = _captureCtx();
    var rcModBad = await cli.main(
      ["api-snapshot", "capture", "--module", path.join(dir, "no-module.js")], cModBad);
    check("api-snapshot capture bad --module → exit 1", rcModBad === 1);
    check("api-snapshot capture bad --module message",
          /cannot load module/.test(cModBad.err()));

    // capture from a valid operator module → wrote snapshot, exit 0
    var customMod = path.join(dir, "custom-mod.js");
    fs.writeFileSync(customMod,
      "module.exports = { version: \"9.9.9\", greet: function greet() {} };");
    var customSnap = path.join(dir, "custom-snap.json");
    var cModOk = _captureCtx();
    var rcModOk = await cli.main(
      ["api-snapshot", "capture", "--file", customSnap, "--module", customMod], cModOk);
    check("api-snapshot capture custom --module → exit 0", rcModOk === 0);
    check("api-snapshot capture custom --module wrote file", fs.existsSync(customSnap));
    check("api-snapshot capture custom --module reports version",
          /frameworkVersion 9\.9\.9/.test(cModOk.out()));

    // capture with a RELATIVE --module path → the `nodePath.resolve(ctx.cwd,
    // modulePath)` arm of _resolveTargetModule (the absolute-path arm is what
    // every other --module test exercises). ctx.cwd is the repo root, so a
    // repo-relative module path resolves.
    var relSnap = path.join(dir, "rel-snap.json");
    var cRel = _captureCtx();
    var rcRel = await cli.main(
      ["api-snapshot", "capture", "--file", relSnap, "--module", "lib/constants.js"], cRel);
    check("api-snapshot capture relative --module → exit 0", rcRel === 0);
    check("api-snapshot capture relative --module wrote file", fs.existsSync(relSnap));

    // compare where the saved snapshot reads fine but capturing the CURRENT
    // surface fails (bad --module) → "cannot capture current surface", exit 1
    var cCmpBad = _captureCtx();
    var rcCmpBad = await cli.main(
      ["api-snapshot", "compare", "--file", customSnap, "--module", path.join(dir, "gone.js")],
      cCmpBad);
    check("api-snapshot compare uncapturable current → exit 1", rcCmpBad === 1);
    check("api-snapshot compare uncapturable current message",
          /cannot capture current surface/.test(cCmpBad.err()));

    // =====================================================================
    // top-level dispatch — help routing edges
    // =====================================================================

    // `<cmd> --help` synthesizes `help <cmd>` → that command's usage
    var cMigHelp = _captureCtx();
    var rcMigHelp = await cli.main(["migrate", "--help"], cMigHelp);
    check("migrate --help → exit 0",             rcMigHelp === 0);
    check("migrate --help prints migrate usage", /Usage: blamejs migrate/.test(cMigHelp.out()));

    // `-h` short flag takes the same route
    var cMigH = _captureCtx();
    var rcMigH = await cli.main(["migrate", "-h"], cMigH);
    check("migrate -h → exit 0",                 rcMigH === 0);
    check("migrate -h prints migrate usage",     /Usage: blamejs migrate/.test(cMigH.out()));

    // `help <unknown-topic>` falls through to the top-level usage
    var cBogus = _captureCtx();
    var rcBogus = await cli.main(["help", "totally-bogus-topic"], cBogus);
    check("help unknown-topic → exit 0",         rcBogus === 0);
    check("help unknown-topic prints top usage", /blamejs <command>/.test(cBogus.out()));
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }

  sectionRepeatableFlags();
  await sectionTopLevel();
  await sectionSeedRun();
  await sectionApiSnapshotBreaking();
  await sectionAudit();
  await sectionFileType();
  await sectionPositionalHelp();
  await sectionArgValidation();
  await sectionBackupRestoreValidation();
  await sectionBootedApiKey();
  await sectionBootedErase();
  await sectionBootedRetention();
  await sectionBootedMtls();
  await sectionBootedSecurity();

  // Additional branch coverage for the remaining error / defensive / option-
  // default paths across every subcommand.
  await sectionMigrate();
  await sectionApiSnapshotEdges();
  await sectionAuditVerifyChainEdges();
  await sectionRestoreEdges();
  await sectionBackupEdges();
  await sectionMtlsEdges();
  await sectionSecurityEdges();
  await sectionConfigDrift();
  await sectionConfigDriftSidecar();
  await sectionVault();
  await sectionPassword();
  await sectionFileTypeEdges();
  await sectionRetentionEdges();
  await sectionEraseEdges();
  await sectionApiKeyEdges();
  await sectionBootedRawTable();
  await sectionTopUnknownCommand();

  // Additional branch coverage: top-level dispatch defaults + per-command
  // help fan-out, adversarial migrate --steps, post-boot required-flag guards
  // (api-key / mtls), default-arg arms, and the operation-body + error paths
  // (audit ops / restore populated-list loops) the omit-one-flag tests miss.
  await sectionTopLevelDispatch2();
  await sectionMigrateMore();
  await sectionApiKeyMore();
  await sectionSecurityMore();
  await sectionCheapGuards();
  await sectionMtlsMore();
  await sectionRestoreMore();
  await sectionAuditOps();
  await sectionRetentionPreviewText();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
