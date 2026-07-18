// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditSign.anchor / verifyAnchor / verifyAnchorChain — the chain-checkpoint
 * protocol lifted off the framework audit store so a consumer can anchor THEIR
 * OWN hash chain with PQC signatures (#327).
 *
 * RED on the current tree: b.auditSign.anchor is undefined. Uses ml-dsa-65 (the
 * fastest PQC keypair) so the per-run keygen stays cheap.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-anchor-"));
  try {
    b.auditSign._resetForTest();
    await b.auditSign.init({ dataDir: dir, mode: "plaintext", algorithm: "ml-dsa-65" });
    var as = b.auditSign;

    check("anchor / verifyAnchor / verifyAnchorChain are exported",
      typeof b.auditSign.anchor === "function" &&
      typeof b.auditSign.verifyAnchor === "function" &&
      typeof b.auditSign.verifyAnchorChain === "function");

    var a1 = as.anchor({ counter: 1, tipHash: "h1" });
    check("anchor returns a self-describing signed object",
      a1 && typeof a1.signature === "string" && a1.tipHash === "h1" &&
      a1.publicKeyFingerprint && a1.format === "blamejs-chain-anchor-v1");
    check("a distinct format magic separates anchors from audit checkpoints",
      a1.format !== "blamejs-audit-checkpoint-v1");

    check("verifyAnchor accepts a clean anchor", as.verifyAnchor(a1).ok === true);

    // A full-chain rewrite changes the tipHash — the signature catches it.
    check("verifyAnchor rejects a tampered tipHash",
      as.verifyAnchor(Object.assign({}, a1, { tipHash: "ffff" })).ok === false);
    // A forged signature (truncated hex) fails closed.
    check("verifyAnchor rejects malformed-hex signature",
      as.verifyAnchor(Object.assign({}, a1, { signature: "zz" })).ok === false);
    // An unknown signing key fails closed.
    check("verifyAnchor rejects an unknown signing-key fingerprint",
      as.verifyAnchor(Object.assign({}, a1, { publicKeyFingerprint: "deadbeef" })).ok === false);

    var a2 = as.anchor({ counter: 2, tipHash: "h2", prevTipHash: "h1" });
    // The linkage is SIGNED (#327 C2): tampering prevTipHash breaks the signature.
    check("prevTipHash is bound into the signature (tampering it breaks verify)",
      as.verifyAnchor(Object.assign({}, a2, { prevTipHash: "wrong" })).ok === false);

    check("verifyAnchorChain accepts a linked, increasing sequence",
      as.verifyAnchorChain([a1, a2]).ok === true && as.verifyAnchorChain([a1, a2]).anchorsVerified === 2);

    // Truncation: a non-genesis anchor presented first (its prevTipHash has no
    // predecessor) is a break.
    var tr = as.verifyAnchorChain([a2]);
    check("verifyAnchorChain catches a dropped predecessor", tr.ok === false && tr.breakAt === 0);

    // A broken link (prevTipHash != prior tipHash) is caught.
    var a3 = as.anchor({ counter: 3, tipHash: "h3", prevTipHash: "not-h2" });
    var br = as.verifyAnchorChain([a1, a2, a3]);
    check("verifyAnchorChain catches a broken link", br.ok === false && br.breakAt === 2);

    // Non-monotonic counters are caught.
    var lower = as.anchor({ counter: 1, tipHash: "h4", prevTipHash: "h2" });
    check("verifyAnchorChain catches a non-increasing counter",
      as.verifyAnchorChain([a1, a2, lower]).ok === false);

    // requireLinkage:false admits unlinked anchors on the signature alone.
    var u1 = as.anchor({ counter: 10, tipHash: "u1" });
    var u2 = as.anchor({ counter: 11, tipHash: "u2" });
    check("requireLinkage:false admits unlinked anchors",
      as.verifyAnchorChain([u1, u2], { requireLinkage: false }).ok === true);

    // Malformed tip throws a typed config-time error.
    var threw = false;
    try { as.anchor({ counter: 1 }); } catch (e) { threw = e.code === "ANCHOR_BAD_TIPHASH"; }
    check("anchor throws a typed error on a malformed tip", threw);

    // ---- Signed-bytes canonicalization: the record delimiter must not be a
    // field value. anchorPayload joins format / counter / tipHash / prevTipHash
    // / createdAt with "\n". If a string field carries a "\n", content can
    // migrate across a field boundary WITHOUT changing the signed bytes, so ONE
    // signature is valid for several different { tipHash, prevTipHash } splits:
    // a signature minted for one split verifies for a boundary-shifted twin,
    // defeating the "prevTipHash is bound into the signature" linkage guarantee.
    // RED before the fix (both twins verified true); fail-closed after.
    var fmt = a1.format;
    var kCounter = 5, kCreatedAt = 99;
    var tipA = "X", prevA = "Y\nZ";        // split A
    var tipB = "X\nY", prevB = "Z";        // split B -- identical signed bytes
    var bytesA = Buffer.from(fmt + "\n" + kCounter + "\n" + tipA + "\n" + prevA + "\n" + kCreatedAt, "utf8");
    var bytesB = Buffer.from(fmt + "\n" + kCounter + "\n" + tipB + "\n" + prevB + "\n" + kCreatedAt, "utf8");
    check("two field-boundary splits produce identical signed bytes (the collision)",
      bytesA.equals(bytesB));
    var collisionSig = as.sign(bytesA).toString("hex");
    var collisionBase = {
      format: fmt, counter: kCounter, createdAt: kCreatedAt,
      algorithm: as.getAlgorithm(), publicKeyFingerprint: as.getPublicKeyFingerprint(),
      signature: collisionSig,
    };
    var anchorSplitA = Object.assign({}, collisionBase, { tipHash: tipA, prevTipHash: prevA });
    var anchorSplitB = Object.assign({}, collisionBase, { tipHash: tipB, prevTipHash: prevB });
    check("verifyAnchor fails closed on a delimiter-bearing prevTipHash (canonicalization)",
      as.verifyAnchor(anchorSplitA).ok === false);
    check("verifyAnchor fails closed on the boundary-shifted twin (same signature, different tipHash)",
      as.verifyAnchor(anchorSplitB).ok === false);

    // Sign-side: minting an ambiguous signature is refused up front, so the
    // collision above can never be produced through the public API.
    var threwTipNL = false;
    try { as.anchor({ counter: 1, tipHash: "a\nb" }); }
    catch (e) { threwTipNL = e.code === "ANCHOR_BAD_TIPHASH"; }
    check("anchor refuses a tipHash carrying the record delimiter", threwTipNL);
    var threwPrevNL = false;
    try { as.anchor({ counter: 1, tipHash: "ok", prevTipHash: "a\nb" }); }
    catch (e) { threwPrevNL = e.code === "ANCHOR_BAD_PREV"; }
    check("anchor refuses a prevTipHash carrying the record delimiter", threwPrevNL);
    var threwFmtNL = false;
    try { as.anchor({ counter: 1, tipHash: "ok" }, { format: "my\nledger" }); }
    catch (e) { threwFmtNL = e.code === "ANCHOR_BAD_FORMAT"; }
    check("anchor refuses a format carrying the record delimiter", threwFmtNL);

    // ---- verifyAnchor defensive-reader branches (never throw on adversarial
    // content; return { ok:false }). ----
    check("verifyAnchor rejects a non-object",
      as.verifyAnchor(null).ok === false && as.verifyAnchor(42).ok === false);
    check("verifyAnchor rejects an anchor missing signature / fingerprint",
      as.verifyAnchor({ tipHash: "h1", counter: 1 }).ok === false);
    check("verifyAnchor rejects a non-finite counter",
      as.verifyAnchor(Object.assign({}, a1, { counter: Infinity })).ok === false);

    // ---- verifyAnchorChain adversarial branches ----
    check("verifyAnchorChain rejects a non-array",
      as.verifyAnchorChain(null).ok === false && as.verifyAnchorChain("nope").ok === false);
    check("verifyAnchorChain on an empty array is a vacuous pass",
      as.verifyAnchorChain([]).ok === true && as.verifyAnchorChain([]).anchorsVerified === 0);
    // Replay: the same anchor twice -> counter not strictly increasing.
    var replay = as.verifyAnchorChain([a1, a2, a2]);
    check("verifyAnchorChain rejects a replayed (duplicate) anchor",
      replay.ok === false && replay.breakAt === 2);
    // Fail-closed default: linkage is REQUIRED unless the caller opts out, so an
    // operator who forgets prevTipHash does not silently get the weaker guarantee.
    var unlinkedDefault = as.verifyAnchorChain([u1, u2]);
    check("verifyAnchorChain requires linkage by default (unlinked non-genesis rejected)",
      unlinkedDefault.ok === false && unlinkedDefault.breakAt === 1);

    // ---- fingerprintOf / getPublicKeyByFingerprint ----
    var threwFpEmpty = false;
    try { as.fingerprintOf(""); } catch (e) { threwFpEmpty = e.code === "audit-sign/bad-public-key"; }
    var threwFpType = false;
    try { as.fingerprintOf(123); } catch (e) { threwFpType = e.code === "audit-sign/bad-public-key"; }
    check("fingerprintOf throws a typed error on empty / non-string input",
      threwFpEmpty && threwFpType);
    check("fingerprintOf matches getPublicKeyFingerprint for the live key",
      as.fingerprintOf(as.getPublicKey()) === as.getPublicKeyFingerprint());
    check("getPublicKeyByFingerprint returns null for an unknown fingerprint",
      as.getPublicKeyByFingerprint("00ff00ff") === null);

    // ---- reSignAll: re-sign valid, SKIP tampered / empty, never abort ----
    var reSignSeen = [];
    var okPayload = Buffer.from("resign-ok", "utf8");
    var okEntry = { id: 1, payload: okPayload, signature: as.sign(okPayload), oldPublicKeyPem: as.getPublicKey() };
    var tamperedEntry = {
      id: 2, payload: Buffer.from("resign-tampered", "utf8"),
      signature: as.sign(Buffer.from("a-different-payload", "utf8")),   // sig over other bytes -> fails verify
      oldPublicKeyPem: as.getPublicKey(),
    };
    async function* reSignEntries() { yield okEntry; yield tamperedEntry; yield { id: 3 }; }
    var summary = await as.reSignAll(reSignEntries(), {
      onProgress: function (e) { reSignSeen.push(e.id); },
    });
    check("reSignAll re-signs the valid entry and skips tampered + empty",
      summary.reSigned === 1 && summary.skipped === 2 && summary.errors === 0);
    check("reSignAll onProgress fires only for the re-signed entry",
      reSignSeen.length === 1 && reSignSeen[0] === 1);

    // ---- Key-rotation boundary ----
    var beforeFp = as.getPublicKeyFingerprint();
    var preRotAnchor = as.anchor({ counter: 200, tipHash: "rot-tip" });
    check("anchor verifies before rotation", as.verifyAnchor(preRotAnchor).ok === true);
    // Negative rotations first (no state change): ROTATE_NOOP + ROTATE_BAD_ALG.
    var threwNoop = false;
    try { await as.rotateSigningKey({ publicKeyPem: as.getPublicKey(), privateKeyPem: "unused-for-noop-check" }); }
    catch (e) { threwNoop = e.code === "ROTATE_NOOP"; }
    check("rotateSigningKey refuses a no-op rotation (identical fingerprint)", threwNoop);
    var threwBadAlg = false;
    try {
      await as.rotateSigningKey({
        publicKeyPem: "-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----",
        privateKeyPem: "unused", algorithm: "not-a-real-alg",
      });
    } catch (e) { threwBadAlg = e.code === "ROTATE_BAD_ALG"; }
    check("rotateSigningKey refuses an unsupported algorithm", threwBadAlg);
    check("failed rotations left the live key untouched", as.getPublicKeyFingerprint() === beforeFp);

    // Real rotation: fresh key generated, old public key archived to the
    // unsealed history so pre-rotation anchors still verify.
    var rot = await as.rotateSigningKey();
    check("rotation changed the live fingerprint",
      rot.newFingerprint !== beforeFp && as.getPublicKeyFingerprint() === rot.newFingerprint);
    check("pre-rotation anchor still verifies after rotation (history resolves the old key)",
      as.verifyAnchor(preRotAnchor).ok === true);
    check("getPublicKeyByFingerprint resolves the rotated-out key",
      typeof as.getPublicKeyByFingerprint(beforeFp) === "string");
    var postRotAnchor = as.anchor({ counter: 201, tipHash: "rot-tip-2", prevTipHash: "rot-tip" });
    check("post-rotation anchor verifies under the new key",
      as.verifyAnchor(postRotAnchor).ok === true &&
      postRotAnchor.publicKeyFingerprint === rot.newFingerprint);
    check("a chain spanning the rotation boundary verifies end-to-end",
      as.verifyAnchorChain([preRotAnchor, postRotAnchor]).ok === true);
  } finally {
    try { b.auditSign._resetForTest(); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () {
    console.log("OK - audit-sign-anchor tests (" + helpers.getChecks() + " checks)");
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
