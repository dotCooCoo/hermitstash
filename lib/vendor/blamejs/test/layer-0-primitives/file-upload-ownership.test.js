// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * file-upload — per-upload OWNERSHIP is enforced (IDOR / CWE-639).
 *
 * init() records the upload's owner (actor.id || actor.userId). Every
 * subsequent lifecycle call (acceptChunk / finalize / status / cancelUpload)
 * refuses a caller who is not the owner — even when that caller holds the
 * coarse "fileUpload.<op>" capability scope. Actor A's own calls succeed
 * (positive control). The allowCrossActor escape hatch (plus the
 * "fileUpload.admin" scope when permissions are wired) restores cross-actor
 * access for operator admin tooling.
 *
 * RED on the pre-fix tree: B's finalize / cancelUpload / status / acceptChunk
 * on A's uploadId SUCCEED (no owner comparison exists).
 */
var nodeOs = require("node:os");
var nodePath = require("node:path");
var nodeFs = require("node:fs");
var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var ACTOR_A = { id: "actor-a" };
var ACTOR_B = { id: "actor-b" };

function _tmpDir(suffix) {
  var dir = nodePath.join(nodeOs.tmpdir(), "fileupload-ownership-" + suffix + "-" +
    nodeCrypto.randomBytes(6).toString("hex"));
  nodeFs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}
function _chunkSha3(buf) { return require("../../lib/crypto").sha3Hash(buf); }
function _fullSha3(pieces) {
  var h = nodeCrypto.createHash("sha3-512");
  for (var i = 0; i < pieces.length; i++) h.update(pieces[i]);
  return h.digest("hex");
}
function _manifestFor(pieces) {
  var total = 0;
  for (var i = 0; i < pieces.length; i++) total += pieces[i].length;
  return {
    totalBytes: total,
    sha3:       _fullSha3(pieces),
    chunks:     pieces.map(function (p, idx) { return { index: idx, sha3: _chunkSha3(p) }; }),
  };
}
// Drive init + one chunk for `actor`, leaving the upload READY to finalize.
async function _seedUpload(u, uploadId, pieces, actor) {
  await u.init({ uploadId: uploadId, actor: actor, metadata: { filename: "doc.txt" } });
  for (var i = 0; i < pieces.length; i++) {
    await u.acceptChunk({ uploadId: uploadId, index: i, body: pieces[i],
                          sha3: _chunkSha3(pieces[i]), actor: actor });
  }
}
async function _expectThrows(fn) {
  try { await fn(); return null; }
  catch (e) { return e; }
}

async function run() {
  var pieces = [Buffer.from("hello ownership", "utf8")];

  // A permissions instance that GRANTS every coarse fileUpload.* scope to BOTH
  // actors (but NOT fileUpload.admin) — so the cross-actor refusal comes from
  // per-upload ownership, not the capability scope.
  var coarsePerms = {
    check: function (actor, scope) {
      if (scope === "fileUpload.admin") return false;   // no admin for anyone here
      return true;                                       // every other fileUpload.* scope granted
    },
  };

  // ---- Cross-actor finalize is REFUSED (this is the RED assertion) ----
  {
    var u = b.fileUpload.create({
      stagingDir:     _tmpDir("finalize"),
      filenameSafety: null, contentSafety: null,
      permissions:    coarsePerms,
    });
    await _seedUpload(u, "u-own-1", pieces, ACTOR_A);
    var manifest = _manifestFor(pieces);

    var bErr = await _expectThrows(function () {
      return u.finalize({ uploadId: "u-own-1", manifest: manifest, actor: ACTOR_B });
    });
    // RED ON CURRENT TREE: B's finalize SUCCEEDS today → bErr === null → fails.
    check("ownership[finalize]: actor B cannot finalize A's upload",
          bErr !== null && bErr.code === "OWNERSHIP_VIOLATION");

    // Positive control — the owner CAN finalize.
    var aRv = await u.finalize({ uploadId: "u-own-1", manifest: manifest, actor: ACTOR_A });
    check("ownership[finalize]: owner A finalizes successfully",
          aRv && aRv.ok === true && aRv.size === pieces[0].length);
  }

  // ---- Cross-actor cancelUpload is REFUSED ----
  {
    var u2 = b.fileUpload.create({
      stagingDir:     _tmpDir("cancel"),
      filenameSafety: null, contentSafety: null,
      permissions:    coarsePerms,
    });
    await _seedUpload(u2, "u-own-2", pieces, ACTOR_A);

    var cErr = await _expectThrows(function () {
      return u2.cancelUpload("u-own-2", { actor: ACTOR_B });
    });
    // RED: B's cancel returns { ok:true } today (deletes A's staging) → cErr === null.
    check("ownership[cancel]: actor B cannot cancel A's upload",
          cErr !== null && cErr.code === "OWNERSHIP_VIOLATION");

    // Positive control — the upload still exists and the owner can cancel it.
    var aCancel = await u2.cancelUpload("u-own-2", { actor: ACTOR_A });
    check("ownership[cancel]: owner A cancels successfully",
          aCancel && aCancel.ok === true);
  }

  // ---- Cross-actor status is REFUSED ----
  {
    var u3 = b.fileUpload.create({
      stagingDir:     _tmpDir("status"),
      filenameSafety: null, contentSafety: null,
      permissions:    coarsePerms,
    });
    await _seedUpload(u3, "u-own-3", pieces, ACTOR_A);

    var sErr = await _expectThrows(function () {
      return u3.status("u-own-3", { actor: ACTOR_B });
    });
    // RED: B's status returns A's metadata today → sErr === null.
    check("ownership[status]: actor B cannot read A's upload status",
          sErr !== null && sErr.code === "OWNERSHIP_VIOLATION");

    // Positive control — the owner reads status.
    var aStatus = u3.status("u-own-3", { actor: ACTOR_A });
    check("ownership[status]: owner A reads status successfully",
          aStatus && aStatus.uploadId === "u-own-3");
  }

  // ---- Cross-actor acceptChunk is REFUSED ----
  {
    var u4 = b.fileUpload.create({
      stagingDir:     _tmpDir("accept"),
      filenameSafety: null, contentSafety: null,
      permissions:    coarsePerms,
    });
    await u4.init({ uploadId: "u-own-4", actor: ACTOR_A, metadata: {} });

    var extra = Buffer.from("interloper chunk", "utf8");
    var acErr = await _expectThrows(function () {
      return u4.acceptChunk({ uploadId: "u-own-4", index: 0, body: extra,
                              sha3: _chunkSha3(extra), actor: ACTOR_B });
    });
    // RED: B's acceptChunk writes a chunk into A's upload today → acErr === null.
    check("ownership[accept]: actor B cannot push a chunk to A's upload",
          acErr !== null && acErr.code === "OWNERSHIP_VIOLATION");

    // Positive control — the owner can push.
    var aAccept = await u4.acceptChunk({ uploadId: "u-own-4", index: 0, body: pieces[0],
                                         sha3: _chunkSha3(pieces[0]), actor: ACTOR_A });
    check("ownership[accept]: owner A pushes a chunk successfully",
          aAccept && aAccept.received === 1);
  }

  // ---- Escape hatch: allowCrossActor + fileUpload.admin scope ALLOWS cross-actor ----
  {
    var adminPerms = {
      check: function () { return true; },   // grants fileUpload.admin too
    };
    var u5 = b.fileUpload.create({
      stagingDir:      _tmpDir("admin"),
      filenameSafety:  null, contentSafety: null,
      permissions:     adminPerms,
      allowCrossActor: true,
    });
    await _seedUpload(u5, "u-own-5", pieces, ACTOR_A);
    var manifest5 = _manifestFor(pieces);

    // B (admin) finalizes A's upload — the opt actually works.
    var adminRv = await u5.finalize({ uploadId: "u-own-5", manifest: manifest5, actor: ACTOR_B });
    check("ownership[admin]: allowCrossActor + admin scope lets B finalize A's upload",
          adminRv && adminRv.ok === true);
  }

  // ---- Escape hatch is GATED: allowCrossActor WITHOUT the admin scope is refused ----
  {
    var u6 = b.fileUpload.create({
      stagingDir:      _tmpDir("admin-denied"),
      filenameSafety:  null, contentSafety: null,
      permissions:     coarsePerms,        // grants everything EXCEPT fileUpload.admin
      allowCrossActor: true,
    });
    await _seedUpload(u6, "u-own-6", pieces, ACTOR_A);
    var manifest6 = _manifestFor(pieces);

    var gateErr = await _expectThrows(function () {
      return u6.finalize({ uploadId: "u-own-6", manifest: manifest6, actor: ACTOR_B });
    });
    check("ownership[admin-gated]: allowCrossActor still requires the fileUpload.admin scope",
          gateErr !== null && gateErr.code === "PERMISSION_DENIED");
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
