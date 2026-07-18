// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.atomicFile.cleanOrphans boot-time orphan sweep.
 *
 * A crashed atomic write leaves a sibling temp file named
 * `<filepath>.tmp-<token>`. cleanOrphans globs those by prefix and prunes
 * the ones older than `olderThanMs` (default 5 minutes), leaving fresh
 * in-flight temps and every unrelated file untouched. This drives the real
 * consumer path: real orphan temp files planted in a scratch dir, aged past
 * the threshold via mtime backdating, then swept.
 */

var helpers      = require("../helpers");
var check        = helpers.check;
var b            = helpers.b;
var backdateFile = helpers.backdateFile;
var os           = require("node:os");
var path         = require("node:path");
var fs           = require("node:fs");

function _plant(fp, token, body) {
  var p = fp + ".tmp-" + token;
  fs.writeFileSync(p, body || token);
  return p;
}

function testCleanOrphansDefault() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-orphan-def-"));
  var fp  = path.join(dir, "vault.key.sealed");
  try {
    // Files that MUST survive: the real sealed file + an unrelated sibling.
    fs.writeFileSync(fp, "real-sealed-contents");
    var unrelated = path.join(dir, "other.txt");
    fs.writeFileSync(unrelated, "leave-me");

    // Stale orphan, aged an hour into the past (well past the 5-min default).
    var stale = _plant(fp, "staleaaaa");
    backdateFile(stale);
    // Fresh in-flight temp (mtime ~now) — MUST survive the default sweep.
    var fresh = _plant(fp, "freshbbbb");

    // Default olderThanMs is documented as 300000 (5 minutes).
    var removed = b.atomicFile.cleanOrphans(fp);
    check("atomicFile.cleanOrphans: default removes the stale orphan", removed === 1);
    check("atomicFile.cleanOrphans: stale orphan unlinked", !fs.existsSync(stale));
    check("atomicFile.cleanOrphans: fresh temp survives default", fs.existsSync(fresh));
    check("atomicFile.cleanOrphans: real sealed file untouched", fs.existsSync(fp));
    check("atomicFile.cleanOrphans: unrelated sibling untouched", fs.existsSync(unrelated));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testCleanOrphansExplicitThreshold() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-orphan-thr-"));
  var fp  = path.join(dir, "db.enc");
  try {
    var stale1 = _plant(fp, "aaaa");
    var stale2 = _plant(fp, "bbbb");
    backdateFile(stale1);
    backdateFile(stale2);
    var fresh = _plant(fp, "cccc");

    var removed = b.atomicFile.cleanOrphans(fp, { olderThanMs: 300000 });
    check("atomicFile.cleanOrphans: explicit threshold removes both stale", removed === 2);
    check("atomicFile.cleanOrphans: stale1 gone", !fs.existsSync(stale1));
    check("atomicFile.cleanOrphans: stale2 gone", !fs.existsSync(stale2));
    check("atomicFile.cleanOrphans: fresh temp survives", fs.existsSync(fresh));

    // Age is the sole driver: once the surviving temp is itself aged past
    // the threshold, the next sweep prunes it too. (Backdating avoids the
    // fs-mtime-granularity knife-edge of a just-created file at age 0.)
    backdateFile(fresh);
    var removedAged = b.atomicFile.cleanOrphans(fp, { olderThanMs: 300000 });
    check("atomicFile.cleanOrphans: newly-aged temp now pruned", removedAged === 1);
    check("atomicFile.cleanOrphans: aged temp gone", !fs.existsSync(fresh));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testCleanOrphansNoOrphans() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-orphan-none-"));
  var fp  = path.join(dir, "audit-sign.key.sealed");
  try {
    fs.writeFileSync(fp, "sealed");
    // A same-directory temp for a DIFFERENT basename must not be swept —
    // the prefix match is anchored to this filepath's basename.
    var otherTemp = path.join(dir, "vault.key.sealed.tmp-zzzz");
    fs.writeFileSync(otherTemp, "not-mine");
    backdateFile(otherTemp);

    var removed = b.atomicFile.cleanOrphans(fp, { olderThanMs: 300000 });
    check("atomicFile.cleanOrphans: no matching orphans → 0", removed === 0);
    check("atomicFile.cleanOrphans: foreign-basename temp untouched", fs.existsSync(otherTemp));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function run() {
  testCleanOrphansDefault();
  testCleanOrphansExplicitThreshold();
  testCleanOrphansNoOrphans();
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("OK — " + helpers.getChecks() + " checks passed");
}
