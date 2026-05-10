"use strict";
/**
 * b.network.tls.ct.verifyInclusion + verifyConsistency — RFC 9162
 * Certificate Transparency v2 inclusion-proof + consistency-proof
 * verification.
 *
 * The inclusion path constructs a synthetic Merkle tree, derives the
 * audit path for a leaf, and asserts the framework recovers the same
 * root the construction produced. The consistency path covers both
 * the "first tree is a complete subtree" branch and the "first tree
 * is incomplete" branch (RFC 9162 §2.1.4).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var nodeCrypto = require("crypto");

function _leafHash(d) {
  return nodeCrypto.createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x00]), d])).digest();
}
function _innerHash(l, r) {
  return nodeCrypto.createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x01]), l, r])).digest();
}

function testSurface() {
  check("network.tls.ct.verifyInclusion is a function",
        typeof b.network.tls.ct.verifyInclusion === "function");
  check("network.tls.ct.verifyConsistency is a function",
        typeof b.network.tls.ct.verifyConsistency === "function");
}

function testConsistencyCompleteSubtree() {
  // 4-leaf tree.
  var leaves = [Buffer.from("a"), Buffer.from("b"),
                Buffer.from("c"), Buffer.from("d")];
  var lh = leaves.map(_leafHash);
  var n01 = _innerHash(lh[0], lh[1]);
  var n23 = _innerHash(lh[2], lh[3]);
  var root = _innerHash(n01, n23);

  // m=2 (complete subtree, root=n01) → n=4 (root). Proof = [n23].
  var ok = b.network.tls.ct.verifyConsistency({
    firstSize:  2,
    firstRoot:  n01,
    secondSize: 4,
    secondRoot: root,
    proof:      [n23],
  });
  check("consistency m=2→n=4 (complete subtree) verifies",
        ok.valid === true);

  // Tampered root refuses.
  var tampered = Buffer.from(root);
  tampered[0] ^= 0x01;
  var bad = b.network.tls.ct.verifyConsistency({
    firstSize:  2,
    firstRoot:  n01,
    secondSize: 4,
    secondRoot: tampered,
    proof:      [n23],
  });
  check("consistency tampered second-root refuses",
        bad.valid === false && bad.reason === "root-mismatch");
}

function testConsistencyIncompleteSubtree() {
  var leaves = [Buffer.from("a"), Buffer.from("b"),
                Buffer.from("c"), Buffer.from("d")];
  var lh = leaves.map(_leafHash);
  var n01 = _innerHash(lh[0], lh[1]);
  var n23 = _innerHash(lh[2], lh[3]);
  var root = _innerHash(n01, n23);
  var firstRootM3 = _innerHash(n01, _leafHash(leaves[2]));

  // m=3 → n=4. Proof = [lh[2], lh[3], n01] (RFC 9162 §2.1.4 algorithm).
  var ok = b.network.tls.ct.verifyConsistency({
    firstSize:  3,
    firstRoot:  firstRootM3,
    secondSize: 4,
    secondRoot: root,
    proof:      [lh[2], lh[3], n01],
  });
  check("consistency m=3→n=4 (incomplete subtree) verifies",
        ok.valid === true);
}

function testInclusionStandalone() {
  // Build a stripped 4-leaf cert tree using fixed bytes for each leaf
  // that match what _ctLeafHash would compute on a minimal
  // MerkleTreeLeaf. Since verifyInclusion expects a leafCertificate
  // and reconstructs leafBytes internally, we exercise the underlying
  // walker via verifyConsistency (already covered) and by running the
  // public API end-to-end against a mocked SCT + signedEntryDer.
  var fakeSignedEntry = Buffer.from("CERT-DER-BYTES");
  var ts = 1700000000000;
  // Reconstruct what _ctLeafHash would produce inside the lib.
  var tsBuf = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(ts));
  var lenBuf = Buffer.alloc(3);
  lenBuf.writeUIntBE(fakeSignedEntry.length, 0, 3);
  var leafBytes = Buffer.concat([
    Buffer.from([0x00]),                         // version
    Buffer.from([0x00]),                         // leaf_type timestamped_entry
    tsBuf,
    Buffer.from([0x00, 0x00]),                   // entry_type x509_entry
    lenBuf, fakeSignedEntry,
    Buffer.from([0x00, 0x00]),                   // empty extensions
  ]);
  var leafHash = _leafHash(leafBytes);

  // 2-leaf tree with this leaf at index 0; sibling = lh1.
  var sibling = nodeCrypto.randomBytes(32);
  var root = _innerHash(leafHash, sibling);

  var rv = b.network.tls.ct.verifyInclusion({
    sct: { logIdHex: "abc", timestamp: ts, signedEntryDer: fakeSignedEntry },
    leafCertificate: Buffer.from("placeholder"),     // not used when signedEntryDer is supplied
    leafIndex: 0,
    auditPath: [sibling],
    sthFromLog: { treeSize: 2, rootHash: root },
  });
  check("inclusion proof for 2-leaf tree verifies",
        rv.valid === true);

  // Tampered audit path refuses.
  var bad = b.network.tls.ct.verifyInclusion({
    sct: { logIdHex: "abc", timestamp: ts, signedEntryDer: fakeSignedEntry },
    leafCertificate: Buffer.from("placeholder"),
    leafIndex: 0,
    auditPath: [nodeCrypto.randomBytes(32)],
    sthFromLog: { treeSize: 2, rootHash: root },
  });
  check("inclusion with tampered audit path refuses",
        bad.valid === false && bad.reason === "root-mismatch");
}

function testValidationPaths() {
  var bad1 = b.network.tls.ct.verifyInclusion(null);
  check("verifyInclusion(null) returns missing-opts",
        bad1.valid === false && bad1.reason === "missing-opts");

  var bad2 = b.network.tls.ct.verifyInclusion({
    sct: { logIdHex: "x", timestamp: 0, signedEntryDer: Buffer.from("e") },
    leafCertificate: Buffer.from("c"),
    leafIndex: -1,
    auditPath: [],
    sthFromLog: { treeSize: 1, rootHash: Buffer.alloc(32) },
  });
  check("negative leafIndex refuses",
        bad2.valid === false && bad2.reason === "bad-leaf-index");

  var bad3 = b.network.tls.ct.verifyConsistency({
    firstSize: 2, secondSize: 4,
    firstRoot: "not-hex-zz",
    secondRoot: Buffer.alloc(32),
    proof: [],
  });
  check("bad first-root encoding refuses",
        bad3.valid === false &&
        (bad3.reason === "bad-first-root" || bad3.reason === "bad-first-root-encoding"));
}

async function run() {
  testSurface();
  testConsistencyCompleteSubtree();
  testConsistencyIncompleteSubtree();
  testInclusionStandalone();
  testValidationPaths();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
