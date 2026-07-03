// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.vault.getDefaultStore — the default sealed-storage Store ({ seal, unseal })
 * that b.cert.create and other sealed-disk consumers resolve when no explicit
 * vault is passed. It previously did not exist, so the documented cert default
 * path threw `TypeError: vault(...).getDefaultStore is not a function`.
 */

var b = require("../..");
var check = require("../helpers/check").check;
var fs = require("fs");
var path = require("path");
var os = require("os");

async function run() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-defstore-"));
  try {
    await b.vault.init({ dataDir: tmp, mode: "plaintext" });

    check("vault.getDefaultStore is a function", typeof b.vault.getDefaultStore === "function");
    var store = b.vault.getDefaultStore();
    check("getDefaultStore() exposes seal + unseal",
          store && typeof store.seal === "function" && typeof store.unseal === "function");

    // Round-trip a payload through the default store (the load-bearing
    // guarantee; at-rest encryption strength is mode-dependent and covered by
    // the wrapped-mode vault tests — here the vault is plaintext for speed).
    var plain = "default-store-secret-not-real";
    var sealed = store.seal(plain);
    check("default store seal emits a vault-prefixed value",
          typeof sealed === "string" && sealed.indexOf("vault:") === 0);
    check("default store unseals back to the original", store.unseal(sealed) === plain);

    check("vault.Store exposes the same seal/unseal pair",
          b.vault.Store && typeof b.vault.Store.seal === "function" && typeof b.vault.Store.unseal === "function");

    console.log("OK — vault.getDefaultStore (" + (require("../helpers").getChecks ? require("../helpers").getChecks() : "?") + " checks)");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
