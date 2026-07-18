// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * vault.getCurrentPassphrase — returns the Buffer the vault was unsealed
 * with on this boot (wrapped mode), or null in plaintext mode.
 *
 * Uses the shared vault-only fixture (wrapped, Argon2id-derived AEAD wrap
 * with the test passphrase from BLAMEJS_VAULT_PASSPHRASE) and a direct
 * plaintext init for the null path.
 *
 * Run standalone: `node test/layer-0-primitives/vault.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b                 = helpers.b;
var fs                = helpers.fs;
var os                = helpers.os;
var path              = helpers.path;
var check             = helpers.check;
var setupVaultOnly    = helpers.setupVaultOnly;
var teardownVaultOnly = helpers.teardownVaultOnly;
var TEST_PASSPHRASE   = helpers.TEST_PASSPHRASE;

async function testGetCurrentPassphraseWrapped() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-wrapped-"));
  await setupVaultOnly(tmpDir);
  try {
    check("vault mode is wrapped after fixture init", b.vault.getMode() === "wrapped");
    var pass = b.vault.getCurrentPassphrase();
    check("vault.getCurrentPassphrase returns a Buffer in wrapped mode",
          Buffer.isBuffer(pass));
    check("vault.getCurrentPassphrase Buffer decodes to the unseal passphrase",
          pass.toString("utf8") === TEST_PASSPHRASE);
  } finally {
    teardownVaultOnly(tmpDir);
  }
}

async function testGetCurrentPassphrasePlaintext() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-plaintext-"));
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  b.vault._resetForTest();
  try {
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    check("vault mode is plaintext after plaintext init", b.vault.getMode() === "plaintext");
    check("vault.getCurrentPassphrase is null in plaintext mode",
          b.vault.getCurrentPassphrase() === null);
  } finally {
    b.vault._resetForTest();
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

function testGetCurrentPassphraseBeforeInit() {
  b.vault._resetForTest();
  check("vault.getCurrentPassphrase is null before init", b.vault.getCurrentPassphrase() === null);
}

async function run() {
  testGetCurrentPassphraseBeforeInit();
  await testGetCurrentPassphraseWrapped();
  await testGetCurrentPassphrasePlaintext();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[vault] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
