// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.safeArchive.inspect auto-unwrap for v0.12.10
 * recipient + v0.12.11 passphrase envelopes (mirrors the
 * v0.12.15 extract auto-unwrap path).
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testInspectAutoUnwrapRecipient() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var t = b.archive.tar();
  t.addFile("a.json", "{\"x\":1}");
  t.addFile("b.json", "{\"y\":2}");
  var sealed = b.archive.wrap(t.toBuffer(), { recipient: pair });
  var sealedPath = path.join(os.tmpdir(), "insp-r-" + Date.now() + ".bin");
  fs.writeFileSync(sealedPath, sealed, { mode: 0o600 });
  try {
    var summary = await b.safeArchive.inspect({
      source:    sealedPath,
      recipient: pair,
    });
    check("safeArchive.inspect: BAWRP source auto-unwrapped + entries enumerated",
      summary.format === "tar" && summary.entries.length === 2);
    var names = summary.entries.map(function (e) { return e.name; }).sort();
    check("safeArchive.inspect: entry names recovered after unwrap",
      names[0] === "a.json" && names[1] === "b.json");
  } finally {
    try { fs.unlinkSync(sealedPath); } catch (_e) { /* ignore */ }
  }
}

async function testInspectAutoUnwrapPassphrase() {
  var t = b.archive.tar();
  t.addFile("phi.json", "{\"id\":42}");
  var sealed = await b.archive.wrapWithPassphrase(t.toBuffer(), {
    passphrase: "aLongCorrectHorseBatteryStaple9876!Phrase",
  });
  var sealedPath = path.join(os.tmpdir(), "insp-p-" + Date.now() + ".bin");
  fs.writeFileSync(sealedPath, sealed, { mode: 0o600 });
  try {
    var summary = await b.safeArchive.inspect({
      source:     sealedPath,
      passphrase: "aLongCorrectHorseBatteryStaple9876!Phrase",
    });
    check("safeArchive.inspect: BAWPP source auto-unwrapped + entries enumerated",
      summary.format === "tar" && summary.entries.length === 1 &&
      summary.entries[0].name === "phi.json");
  } finally {
    try { fs.unlinkSync(sealedPath); } catch (_e) { /* ignore */ }
  }
}

async function testInspectRefusesMissingKey() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var sealed = b.archive.wrap(Buffer.from("X"), { recipient: pair });
  var sealedPath = path.join(os.tmpdir(), "insp-nor-" + Date.now() + ".bin");
  fs.writeFileSync(sealedPath, sealed, { mode: 0o600 });
  try {
    var refused = null;
    try {
      await b.safeArchive.inspect({ source: sealedPath });
    } catch (e) { refused = e; }
    check("safeArchive.inspect: BAWRP without opts.recipient refused upfront",
      refused && /no-recipient-for-wrap/.test(refused.code || refused.message));
  } finally {
    try { fs.unlinkSync(sealedPath); } catch (_e) { /* ignore */ }
  }
}

async function run() {
  await testInspectAutoUnwrapRecipient();
  await testInspectAutoUnwrapPassphrase();
  await testInspectRefusesMissingKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[safe-archive-inspect-unwrap] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
