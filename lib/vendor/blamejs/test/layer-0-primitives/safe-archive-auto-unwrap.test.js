"use strict";
/**
 * Layer 0 — b.safeArchive.extract auto-unwrap path for v0.12.10
 * recipient + v0.12.11 passphrase envelopes.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testAutoUnwrapRecipient() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var srcDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-auw-src-"));
  fs.writeFileSync(path.join(srcDir, "data.json"), "{\"v\":1}", { mode: 0o600 });
  var t = b.archive.tar();
  t.addFile("data.json", fs.readFileSync(path.join(srcDir, "data.json")));
  var sealed = b.archive.wrap(t.toBuffer(), { recipient: pair });
  var sealedPath = path.join(os.tmpdir(), "auw-r-" + Date.now() + ".bin");
  fs.writeFileSync(sealedPath, sealed, { mode: 0o600 });
  var dest = path.join(os.tmpdir(), "auw-r-dest-" + Date.now());
  try {
    var result = await b.safeArchive.extract({
      source:      sealedPath,
      destination: dest,
      recipient:   pair,
    });
    check("safeArchive.extract: BAWRP envelope auto-unwrapped + extracted",
      result.format === "tar" &&
      fs.readFileSync(path.join(dest, "data.json"), "utf-8") === "{\"v\":1}");
  } finally {
    try { fs.rmSync(srcDir,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.unlinkSync(sealedPath); } catch (_e) { /* ignore */ }
  }
}

async function testAutoUnwrapPassphrase() {
  var srcDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-auw-p-"));
  fs.writeFileSync(path.join(srcDir, "data.json"), "{\"v\":2}", { mode: 0o600 });
  var t = b.archive.tar();
  t.addFile("data.json", fs.readFileSync(path.join(srcDir, "data.json")));
  var sealed = await b.archive.wrapWithPassphrase(t.toBuffer(), {
    passphrase: "aLongCorrectHorseBatteryStaple9876!Phrase",
  });
  var sealedPath = path.join(os.tmpdir(), "auw-p-" + Date.now() + ".bin");
  fs.writeFileSync(sealedPath, sealed, { mode: 0o600 });
  var dest = path.join(os.tmpdir(), "auw-p-dest-" + Date.now());
  try {
    var result = await b.safeArchive.extract({
      source:      sealedPath,
      destination: dest,
      passphrase:  "aLongCorrectHorseBatteryStaple9876!Phrase",
    });
    check("safeArchive.extract: BAWPP envelope auto-unwrapped + extracted",
      result.format === "tar" &&
      fs.readFileSync(path.join(dest, "data.json"), "utf-8") === "{\"v\":2}");
  } finally {
    try { fs.rmSync(srcDir,  { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.unlinkSync(sealedPath); } catch (_e) { /* ignore */ }
  }
}

async function testAutoUnwrapRefusesMissingRecipient() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var sealed = b.archive.wrap(Buffer.from("X"), { recipient: pair });
  var sealedPath = path.join(os.tmpdir(), "auw-nor-" + Date.now() + ".bin");
  fs.writeFileSync(sealedPath, sealed, { mode: 0o600 });
  var refused = null;
  try {
    await b.safeArchive.extract({
      source:      sealedPath,
      destination: path.join(os.tmpdir(), "auw-nor-d-" + Date.now()),
    });
  } catch (e) { refused = e; }
  check("safeArchive.extract: BAWRP without opts.recipient refused upfront",
    refused && /no-recipient-for-wrap/.test(refused.code || refused.message));
  try { fs.unlinkSync(sealedPath); } catch (_e) { /* ignore */ }
}

async function testAutoUnwrapRefusesMissingPassphrase() {
  var sealed = await b.archive.wrapWithPassphrase(Buffer.from("X"), {
    passphrase: "aLongCorrectHorseBatteryStaple9876!Phrase",
  });
  var sealedPath = path.join(os.tmpdir(), "auw-nop-" + Date.now() + ".bin");
  fs.writeFileSync(sealedPath, sealed, { mode: 0o600 });
  var refused = null;
  try {
    await b.safeArchive.extract({
      source:      sealedPath,
      destination: path.join(os.tmpdir(), "auw-nop-d-" + Date.now()),
    });
  } catch (e) { refused = e; }
  check("safeArchive.extract: BAWPP without opts.passphrase refused upfront",
    refused && /no-passphrase-for-wrap/.test(refused.code || refused.message));
  try { fs.unlinkSync(sealedPath); } catch (_e) { /* ignore */ }
}

async function run() {
  await testAutoUnwrapRecipient();
  await testAutoUnwrapPassphrase();
  await testAutoUnwrapRefusesMissingRecipient();
  await testAutoUnwrapRefusesMissingPassphrase();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[safe-archive-auto-unwrap] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
