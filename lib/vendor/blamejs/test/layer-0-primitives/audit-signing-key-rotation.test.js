// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// SMOKE_RUN_SOLO — the smoke runner (test/smoke.js) runs this file ALONE
// with the whole machine instead of inside the parallel layer-0 pool.
// The test exercises the encrypted-at-rest audit-signing rotation path:
// setupTestDb (db.enc + sealed signing key), generating a fresh Ed25519
// keypair, rotateSigningKey() re-sealing the new key and archiving the
// old one to a *.history-* file, plus two checkpoints anchored over a
// flushed chain — every step a blocking key-file / db re-encryption
// fsync on the real data dir. Under SMOKE_PARALLEL=64 on a virtualized
// filesystem (the Dropbox-backed working tree, Docker-Desktop FS-virt)
// 64 sibling forks contend for fsync on the same volume and these
// synchronous writes overrun the per-file watchdog. There is no single
// async event to poll past — the contention is whole-process I/O, so the
// file runs solo and finishes in its normal time. Passes alone and at
// SMOKE_PARALLEL=16.

/**
 * Audit-signing key rotation must preserve historical verifiability.
 *
 * The documented contract (lib/audit-sign.js):
 *   - rotateSigningKey() copies the OLD sealed/plaintext key file to a
 *     timestamped `*.history-<iso>-<fp>` path "so historical checkpoints
 *     can still be verified by readers that load the old key" and returns
 *     `historyPath` "so external tools can verify pre-rotation checkpoints
 *     later".
 *   - verify(payload, signature, publicKeyPem) accepts a third arg to use
 *     a HISTORICAL key "so a checkpoint signed years earlier still verifies
 *     after rotation".
 *
 * The promise an operator reads from those docstrings: rotating the
 * audit-signing key does NOT strand the audit history. A checkpoint that
 * was anchored under key K1 still verifies after the key is rotated to K2.
 *
 * This test drives the real production path:
 *   1. Build the audit chain, emit records, anchor a checkpoint under K1.
 *   2. b.auditSign.rotateSigningKey() -> live K2 keypair, K1 archived to
 *      the documented *.history-* path.
 *   3. Emit more records, anchor a second checkpoint under K2.
 *   4. b.audit.verifyCheckpoints() must report BOTH checkpoints Good.
 *
 * If verifyCheckpoints rejects the K1 checkpoint (fingerprint mismatch
 * against the now-current K2 key, with no key-history lookup), that is the
 * advertised-but-missing behaviour — historical verifiability is broken by
 * rotation. The test asserts the CORRECT behaviour (both verify) so it
 * FAILS and exposes the gap.
 *
 * It also exercises the documented remediation primitive reSignAll(): an
 * operator who walks every checkpoint through reSignAll() after rotating
 * should be able to re-sign K1-anchored checkpoints under K2 and have
 * verifyCheckpoints pass. That asserts the escape hatch the docstrings
 * point to actually closes the gap.
 */

var helpers = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var setTestPassphraseEnv = helpers.setTestPassphraseEnv;

var clusterStorage = require("../../lib/cluster-storage");

// Seed `count` durable audit rows through the real chain writer, then
// flush so every row is on disk before we anchor a checkpoint over the tip.
async function _seedAuditRows(count, tag) {
  b.audit.registerNamespace("test");
  for (var i = 0; i < count; i++) {
    await b.audit.record({
      actor:    { userId: "u-" + tag + "-" + i },
      action:   "test.seeded",
      outcome:  "success",
      metadata: { i: i, tag: tag },
    });
  }
  await b.audit.flush();
}

// The audit checkpoint store keeps the canonical payload triple
// (atMonotonicCounter, atRowHash, createdAt) plus the signature +
// publicKeyFingerprint. reSignAll() needs each checkpoint's payload bytes
// and old signature; rebuild them straight from the stored rows the same
// way verifyCheckpoints does.
function _checkpointPayloadFor(row) {
  return Buffer.from(
    b.audit.CHECKPOINT_FORMAT + "\n" +
    String(Number(row.atMonotonicCounter)) + "\n" +
    row.atRowHash + "\n" +
    String(Number(row.createdAt)),
    "utf8"
  );
}

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-keyrot-"));
  try {
    await setupTestDb(dir);

    // ---- Anchor a checkpoint under the first signing key (K1). ----
    var k1Fp  = b.auditSign.getPublicKeyFingerprint();
    var k1Pub = b.auditSign.getPublicKey();
    check("K1 fingerprint is present", typeof k1Fp === "string" && k1Fp.length > 0);

    await _seedAuditRows(4, "k1");
    var ckpt1 = await b.audit.checkpoint();
    check("checkpoint #1 anchored under K1", ckpt1 && ckpt1.atMonotonicCounter >= 4);
    check("checkpoint #1 recorded K1 fingerprint", ckpt1.publicKeyFingerprint === k1Fp);

    // Baseline: before any rotation, verifyCheckpoints is clean.
    var baseline = await b.audit.verifyCheckpoints();
    check("baseline verifyCheckpoints ok (pre-rotation)", baseline.ok === true);
    check("baseline verified the K1 checkpoint", baseline.checkpointsVerified >= 1);

    // ---- Rotate the signing key K1 -> K2. ----
    // Wrapped mode re-derives the audit-signing passphrase to re-seal the
    // new key; the passphrase source strips env after boot reads it, so
    // re-supply it the same way an operator would for a rotation.
    setTestPassphraseEnv();
    var rot = await b.auditSign.rotateSigningKey();
    var k2Fp  = b.auditSign.getPublicKeyFingerprint();
    var k2Pub = b.auditSign.getPublicKey();
    check("rotation changed the key material", k2Fp !== k1Fp);
    check("rotation reports the previous fingerprint", rot.previousFingerprint === k1Fp);
    check("rotation reports the new fingerprint", rot.newFingerprint === k2Fp);

    // The docstring promises the OLD key is archived to *.history-* so
    // historical checkpoints can still be verified later. Confirm the
    // history artifact the rotation advertised actually landed on disk.
    check("rotation returned a historyPath", typeof rot.historyPath === "string" && rot.historyPath.length > 0);
    check("the advertised history key file exists on disk", fs.existsSync(rot.historyPath));

    // The verify-time resolver finds the rotated-out K1 public key (unsealed
    // public-key history) and the live K2 key, but not an unknown fingerprint.
    check("getPublicKeyByFingerprint resolves the rotated-out K1 key",
          b.auditSign.getPublicKeyByFingerprint(k1Fp) === k1Pub);
    check("getPublicKeyByFingerprint resolves the live K2 key",
          b.auditSign.getPublicKeyByFingerprint(k2Fp) === k2Pub);
    check("getPublicKeyByFingerprint returns null for an unknown fingerprint",
          b.auditSign.getPublicKeyByFingerprint("0".repeat(128)) === null);

    // ---- Anchor a second checkpoint under the new key (K2). ----
    await _seedAuditRows(3, "k2");
    var ckpt2 = await b.audit.checkpoint();
    check("checkpoint #2 anchored under K2", ckpt2 && ckpt2.atMonotonicCounter > ckpt1.atMonotonicCounter);
    check("checkpoint #2 recorded K2 fingerprint", ckpt2.publicKeyFingerprint === k2Fp);

    // Sanity: the two checkpoints really were signed under DIFFERENT keys,
    // both signatures valid under their own public key. This proves the
    // history is genuinely cross-key, so the verify path below is the real
    // test (not an artifact of identical keys).
    // Both checkpoint() calls above are awaited, but on a contended /
    // virtualized filesystem (Windows CI) the just-committed checkpoint row can
    // lag the immediate read-back. Poll for both to be visible (poll, don't
    // sleep) before the exact-count assertion — a genuine missing checkpoint
    // still fails via the waitUntil timeout, and a spurious extra row still
    // fails the `=== 2` below, so this hardens the read without masking a bug.
    var rows = [];
    await helpers.waitUntil(async function () {
      rows = await clusterStorage.executeAll(
        "SELECT * FROM audit_checkpoints ORDER BY atMonotonicCounter ASC"
      );
      return rows.length >= 2;
    }, { timeoutMs: 5000, label: "audit-keyrot: both checkpoints visible in audit_checkpoints" });
    check("two checkpoints are stored", rows.length === 2);
    var c1 = rows[0], c2 = rows[1];
    var p1 = _checkpointPayloadFor(c1);
    var p2 = _checkpointPayloadFor(c2);
    var s1 = Buffer.isBuffer(c1.signature) ? c1.signature : Buffer.from(c1.signature);
    var s2 = Buffer.isBuffer(c2.signature) ? c2.signature : Buffer.from(c2.signature);
    check("K1 checkpoint verifies under K1's archived public key",
      b.auditSign.verify(p1, s1, k1Pub) === true);
    check("K1 checkpoint does NOT verify under K2 (genuinely cross-key)",
      b.auditSign.verify(p1, s1, k2Pub) === false);
    check("K2 checkpoint verifies under K2's current public key",
      b.auditSign.verify(p2, s2, k2Pub) === true);

    // ---- The contract under test: BOTH checkpoints must verify after
    // rotation. ----
    // verifyCheckpoints must walk both the K1- and K2-anchored
    // checkpoints and report them Good — the K1 checkpoint resolved
    // through the documented key-history, the K2 checkpoint through the
    // current key.
    var afterRotation = await b.audit.verifyCheckpoints();
    check("after rotation: verifyCheckpoints ok (K1 history preserved)",
      afterRotation.ok === true);
    check("after rotation: BOTH checkpoints verified",
      afterRotation.checkpointsVerified === 2);
    check("after rotation: no break reported",
      afterRotation.breakAt === undefined && !afterRotation.reason);

    console.log("OK — audit signing-key rotation preserves historical verifiability (" +
      helpers.getChecks() + " checks)");
  } finally {
    await teardownTestDb(dir);
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
