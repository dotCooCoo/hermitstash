// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.backup.bundleAdapterStorage — fail closed under the AMBIENT compliance
 * posture, matching b.backup.create.
 *
 * create() resolves the globally-pinned posture via compliance().current()
 * and refuses an unencrypted pipeline under HIPAA / PCI-DSS (and the other
 * BACKUP_ENCRYPTION_REQUIRED_POSTURES). bundleAdapterStorage enforced the
 * same encryption-required gate only when opts.posture named the posture
 * explicitly, so a deployment that pins the posture once with
 * b.compliance.set("hipaa") and constructs the adapter store with the
 * documented default ({ adapter }) slipped a plaintext (cryptoStrategy:
 * "none") bundle store past the gate. The construction path must honour the
 * ambient posture — the same source create() reads.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _stubAdapter() {
  return {
    writeFile: async function () { /* stub */ },
    readFile:  async function () { return Buffer.alloc(0); },
    listKeys:  async function () { return []; },
    deleteKey: async function () { /* stub */ },
    hasKey:    async function () { return false; },
  };
}

function _adapterStorageCode(opts) {
  try { b.backup.bundleAdapterStorage(opts); } catch (e) { return e && e.code; }
  return null;
}

async function run() {
  b.compliance.clear();
  try {
    // Baseline — no ambient posture: the plaintext default constructs cleanly
    // (adapter-encrypted storage is the operator's protective boundary).
    b.compliance.clear();
    check("no posture + cryptoStrategy none (default) constructs",
      _adapterStorageCode({ adapter: _stubAdapter() }) === null);

    // ---- Ambient-posture fail-closed (the reported bug — RED today) ----
    b.compliance.clear();
    b.compliance.set("hipaa");
    // The documented default usage passes only { adapter }; cryptoStrategy
    // defaults to "none", which writes plaintext bundles. Under a globally
    // pinned HIPAA posture the encryption-required gate must refuse here just
    // as create() refuses encrypt:false.
    check("ambient hipaa + default { adapter } (cryptoStrategy none) refused",
      _adapterStorageCode({ adapter: _stubAdapter() }) ===
        "backup/posture-requires-encryption");
    // Explicit cryptoStrategy:"none" under the ambient posture: identical refusal.
    check("ambient hipaa + explicit cryptoStrategy none refused",
      _adapterStorageCode({ adapter: _stubAdapter(), cryptoStrategy: "none" }) ===
        "backup/posture-requires-encryption");
    // A compliant strategy still constructs under the ambient posture.
    check("ambient hipaa + cryptoStrategy recipient constructs",
      _adapterStorageCode({
        adapter:        _stubAdapter(),
        cryptoStrategy: "recipient",
        recipient:      { publicKey: "pk", ecPublicKey: "ec" },
      }) === null);
    b.compliance.clear();

    // ---- Sibling regulated posture via the ambient pin (root, not a one-off) ----
    b.compliance.clear();
    b.compliance.set("pci-dss");
    check("ambient pci-dss + default { adapter } refused",
      _adapterStorageCode({ adapter: _stubAdapter() }) ===
        "backup/posture-requires-encryption");
    b.compliance.clear();

    // A non-encryption-required posture (soc2) must NOT block the plaintext
    // default — the gate is scoped to BACKUP_ENCRYPTION_REQUIRED_POSTURES.
    b.compliance.clear();
    b.compliance.set("soc2");
    check("ambient soc2 + default { adapter } constructs (not encryption-required)",
      _adapterStorageCode({ adapter: _stubAdapter() }) === null);
    b.compliance.clear();

    // ---- Explicit opts.posture still honoured (regression guard) ----
    // A per-call opts.posture override refuses even with no ambient posture,
    // preserving the pre-existing opt-in path.
    b.compliance.clear();
    check("explicit opts.posture=hipaa + none refused (no ambient posture)",
      _adapterStorageCode({ adapter: _stubAdapter(), posture: "hipaa" }) ===
        "backup/posture-requires-encryption");
  } finally {
    b.compliance.clear();
  }
  console.log("OK — backup bundleAdapterStorage ambient-posture fail-closed tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
