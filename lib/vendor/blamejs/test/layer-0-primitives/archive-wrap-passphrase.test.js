"use strict";
/**
 * Layer 0 — b.archive.wrapWithPassphrase + b.archive.unwrapWithPassphrase
 * + bundleAdapterStorage cryptoStrategy: "passphrase" + HIPAA / PCI-DSS
 * entropy floor.
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

var STRONG_PASSPHRASE = "aLongCorrectHorseBatteryStaple9876!Phrase";   // ~227 bits estimated

async function testPassphraseRoundTrip() {
  var src = Buffer.from("opaque archive bytes ".repeat(50));
  var sealed = await b.archive.wrapWithPassphrase(src, {
    passphrase: STRONG_PASSPHRASE,
  });
  check("wrapWithPassphrase: output carries BAWPP magic",
    sealed.slice(0, 5).toString("ascii") === "BAWPP");
  check("wrapWithPassphrase: output version byte present",
    sealed[5] === 0x01);
  var saltLen = sealed[6];
  check("wrapWithPassphrase: saltLen byte sane (16-64 bytes typical)",
    saltLen >= 16 && saltLen <= 64);
  var recovered = await b.archive.unwrapWithPassphrase(sealed, {
    passphrase: STRONG_PASSPHRASE,
  });
  check("wrapWithPassphrase → unwrap: bytes round-trip losslessly",
    recovered.equals(src));
}

async function testPassphraseRefusesBadMagic() {
  var notSealed = Buffer.from("this is not a passphrase envelope");
  var refused = null;
  try {
    await b.archive.unwrapWithPassphrase(notSealed, { passphrase: STRONG_PASSPHRASE });
  } catch (e) { refused = e; }
  check("unwrapWithPassphrase: non-BAWPP input refused with bad-magic",
    refused && /bad-magic/.test(refused.code || refused.message));
}

async function testPassphraseRefusesWrongPassword() {
  var sealed = await b.archive.wrapWithPassphrase(Buffer.from("PHI"), {
    passphrase: STRONG_PASSPHRASE,
  });
  var refused = null;
  try {
    await b.archive.unwrapWithPassphrase(sealed, {
      passphrase: STRONG_PASSPHRASE + "-WRONG",
    });
  } catch (e) { refused = e; }
  check("unwrapWithPassphrase: wrong passphrase refused",
    refused && /decrypt-failed/.test(refused.code || refused.message));
}

async function testPassphraseRefusesWeakEntropy() {
  var refused = null;
  try {
    await b.archive.wrapWithPassphrase(Buffer.from("bytes"), {
      passphrase: "weak",
      minEntropyBits: 80,
    });
  } catch (e) { refused = e; }
  check("wrapWithPassphrase: weak passphrase refused under default floor",
    refused && /weak-passphrase/.test(refused.code || refused.message));
}

async function testBackupPassphraseRoundTrip() {
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-pp-src-"));
  var dest = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-pp-dest-"));
  var verify = path.join(os.tmpdir(), "bjs-pp-verify-" + Date.now());
  try {
    fs.writeFileSync(path.join(src, "phi.json"), "{\"patient\":42}");
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: dest }),
      format:         "tar.gz",
      cryptoStrategy: "passphrase",
      passphrase:     STRONG_PASSPHRASE,
    });
    var bundleId = "2026-05-23T20-15-00-000Z-dddddddd";
    await storage.writeBundle(bundleId, src);
    var sealed = fs.readFileSync(path.join(dest, bundleId, "bundle.tar.gz"));
    check("backup passphrase: bundle on disk carries BAWPP magic",
      sealed.slice(0, 5).toString("ascii") === "BAWPP");
    await storage.readBundle(bundleId, verify);
    check("backup passphrase: phi.json round-trips after unwrap+gunzip+untar",
      fs.readFileSync(path.join(verify, "phi.json"), "utf-8") === "{\"patient\":42}");
  } finally {
    try { fs.rmSync(src,    { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(dest,   { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    try { fs.rmSync(verify, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testBackupPassphraseHipaaRequires128() {
  // HIPAA posture should raise the entropy floor to 128. A 100-bit-
  // estimated passphrase that would pass the 80-bit default must
  // refuse under HIPAA.
  var src = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-pp-hipaa-"));
  try {
    fs.writeFileSync(path.join(src, "phi.json"), "{}");
    var storage = b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: os.tmpdir() }),
      format:         "tar.gz",
      posture:        "hipaa",
      cryptoStrategy: "passphrase",
      passphrase:     "weakish-passphrase17",   // ~100-110 bits estimated
    });
    var refused = null;
    try { await storage.writeBundle("2026-05-23T20-30-00-000Z-eeeeeeee", src); } catch (e) { refused = e; }
    check("backup passphrase: HIPAA raises entropy floor to 128 bits",
      refused && /weak-passphrase/.test(refused.code || refused.message));
  } finally {
    try { fs.rmSync(src, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

async function testPassphraseNanInfinityRefused() {
  // Codex P1 on v0.12.11 PR #162 — typeof NaN === "number" passed
  // the old typeof gate but NaN < 128 is false, bypassing entropy
  // floor under HIPAA. Same for Infinity.
  var refused = null;
  try {
    await b.archive.wrapWithPassphrase(Buffer.from("bytes"), {
      passphrase:     "weak",
      minEntropyBits: NaN,
    });
  } catch (e) { refused = e; }
  check("wrapWithPassphrase: NaN minEntropyBits refused upfront",
    refused && /bad-arg/.test(refused.code || refused.message));
  var refused2 = null;
  try {
    b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: os.tmpdir() }),
      format:         "tar.gz",
      cryptoStrategy: "passphrase",
      passphrase:     "weak",
      posture:        "hipaa",
      passphraseMinEntropyBits: NaN,
    });
  } catch (e) { refused2 = e; }
  check("backup: NaN passphraseMinEntropyBits refused so HIPAA floor can't bypass",
    refused2 && /bad-arg/.test(refused2.code || refused2.message));
}

async function testBufferPassphraseEntropyFromBytes() {
  // Codex P2 on v0.12.11 PR #162 — Buffer passphrases shouldn't
  // be UTF-8 decoded for entropy estimation. A 32-byte CSPRNG
  // buffer should pass an 80-bit floor; the prior code path
  // UTF-8 decoded the random bytes and false-rejected.
  var randomBuf = b.crypto.generateBytes(32);  // 32 unique random bytes typically → ~32 * 5 = 160 bits
  var sealed = await b.archive.wrapWithPassphrase(Buffer.from("PHI"), {
    passphrase:     randomBuf,
    minEntropyBits: 80,
  });
  check("wrapWithPassphrase: Buffer passphrase scored from byte alphabet, not UTF-8 decoding",
    sealed.slice(0, 5).toString("ascii") === "BAWPP");
  // All-zero buffer must still fail — zero alphabet = zero entropy.
  var refused = null;
  try {
    await b.archive.wrapWithPassphrase(Buffer.from("bytes"), {
      passphrase:     Buffer.alloc(64),  // all zeros — one unique byte → 0 bits entropy
      minEntropyBits: 80,
    });
  } catch (e) { refused = e; }
  check("wrapWithPassphrase: all-zero Buffer passphrase refused (zero byte-alphabet)",
    refused && /weak-passphrase/.test(refused.code || refused.message));
}

async function testBackupPassphraseDirectoryRefused() {
  var refused = null;
  try {
    b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: os.tmpdir() }),
      format:         "directory",
      cryptoStrategy: "passphrase",
      passphrase:     STRONG_PASSPHRASE,
    });
  } catch (e) { refused = e; }
  check("backup passphrase: passphrase + directory format refused upfront",
    refused && /passphrase-strategy-needs-bundled-format/.test(refused.code || refused.message));
}

async function run() {
  await testPassphraseRoundTrip();
  await testPassphraseRefusesBadMagic();
  await testPassphraseRefusesWrongPassword();
  await testPassphraseRefusesWeakEntropy();
  await testPassphraseNanInfinityRefused();
  await testBufferPassphraseEntropyFromBytes();
  await testBackupPassphraseRoundTrip();
  await testBackupPassphraseHipaaRequires128();
  await testBackupPassphraseDirectoryRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[archive-wrap-passphrase] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
