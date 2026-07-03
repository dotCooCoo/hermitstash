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
  } finally {
    try { b.auditSign._resetForTest(); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };
