// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.hashFilesParallel — parallel single-pass multi-digest hashing
 * for many files (SBOM regeneration, vendor-data integrity sweeps,
 * release-asset bundling). See lib/crypto.js for the surface contract.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var nc   = require("node:crypto");

function _scratch(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hashparallel-" + label + "-"));
}

function _writeBytes(dir, name, byteLength) {
  var p = path.join(dir, name);
  fs.writeFileSync(p, nc.randomBytes(byteLength));
  return p;
}

function _expectedHex(filePath, alg) {
  return nc.createHash(alg).update(fs.readFileSync(filePath)).digest("hex");
}

function testSurface() {
  check("hashFilesParallel is fn", typeof b.crypto.hashFilesParallel === "function");
}

async function testHappyPath() {
  var dir = _scratch("happy");
  try {
    var paths = [
      _writeBytes(dir, "a.bin", 1024),
      _writeBytes(dir, "b.bin", 4096),
      _writeBytes(dir, "c.bin", 17),
    ];
    var rows = await b.crypto.hashFilesParallel(paths);
    check("result is array of correct length", Array.isArray(rows) && rows.length === paths.length);
    for (var i = 0; i < paths.length; i += 1) {
      check("row " + i + ": path preserved", rows[i].path === paths[i]);
      check("row " + i + ": byteLength accurate", rows[i].byteLength === fs.statSync(paths[i]).size);
      check("row " + i + ": sha256 matches reference",   rows[i].sha256   === _expectedHex(paths[i], "sha256"));
      check("row " + i + ": sha3_512 matches reference", rows[i].sha3_512 === _expectedHex(paths[i], "sha3-512"));
    }
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

async function testOrderPreserved() {
  var dir = _scratch("order");
  try {
    var paths = [];
    for (var i = 0; i < 10; i += 1) {
      paths.push(_writeBytes(dir, "f" + i + ".bin", 64 + i));
    }
    var rows = await b.crypto.hashFilesParallel(paths, { concurrency: 4 });
    var ordered = true;
    for (var j = 0; j < paths.length; j += 1) {
      if (rows[j].path !== paths[j]) ordered = false;
    }
    check("rows match input order under concurrency", ordered);
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

async function testCustomAlgorithms() {
  var dir = _scratch("alg");
  try {
    var p = _writeBytes(dir, "a.bin", 256);
    var rows = await b.crypto.hashFilesParallel([p], { algorithms: ["sha512"] });
    check("custom alg: only sha512 emitted", rows[0].sha512 && !rows[0].sha256);
    check("custom alg: matches reference",   rows[0].sha512 === _expectedHex(p, "sha512"));
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

async function testProgressCallback() {
  var dir = _scratch("progress");
  try {
    var paths = [
      _writeBytes(dir, "a.bin", 64),
      _writeBytes(dir, "b.bin", 128),
      _writeBytes(dir, "c.bin", 256),
    ];
    var calls = [];
    await b.crypto.hashFilesParallel(paths, {
      onProgress: function (completed, total) { calls.push({ c: completed, t: total }); },
    });
    check("onProgress fired N times", calls.length === paths.length);
    check("onProgress reached total",  calls[calls.length - 1].c === paths.length);
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

async function testProgressCallbackErrorsSwallowed() {
  var dir = _scratch("progress-throw");
  try {
    var p = _writeBytes(dir, "a.bin", 32);
    var rows = await b.crypto.hashFilesParallel([p], {
      onProgress: function () { throw new Error("progress callback exploded"); },
    });
    check("progress-throw: result still produced", rows.length === 1 && typeof rows[0].sha256 === "string");
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

async function testEmptyArray() {
  var rows = await b.crypto.hashFilesParallel([]);
  check("empty paths: returns empty array", Array.isArray(rows) && rows.length === 0);
}

async function testBadInputs() {
  async function expectReject(label, p, msgMatch) {
    var threw = null;
    try { await p; } catch (e) { threw = e; }
    check(label, threw && (threw.message || "").indexOf(msgMatch) !== -1);
  }
  await expectReject("non-array filePaths refused",
    b.crypto.hashFilesParallel("not-an-array"),
    "filePaths must be an array");
  await expectReject("empty-string entry refused",
    b.crypto.hashFilesParallel(["valid", ""]),
    "filePaths[1] must be a non-empty string");
  await expectReject("non-array algorithms refused",
    b.crypto.hashFilesParallel(["x"], { algorithms: "sha256" }),
    "opts.algorithms must be a non-empty array");
  await expectReject("zero-length algorithms refused",
    b.crypto.hashFilesParallel(["x"], { algorithms: [] }),
    "opts.algorithms must be a non-empty array");
  await expectReject("bad-shape algorithm entry refused",
    b.crypto.hashFilesParallel(["x"], { algorithms: [""] }),
    "opts.algorithms[0] must be a non-empty string");
  await expectReject("concurrency 0 refused",
    b.crypto.hashFilesParallel(["x"], { concurrency: 0 }),
    "opts.concurrency must be an integer in [1, 256]");
  await expectReject("concurrency 999 refused",
    b.crypto.hashFilesParallel(["x"], { concurrency: 999 }),
    "opts.concurrency must be an integer in [1, 256]");
  await expectReject("non-fn onProgress refused",
    b.crypto.hashFilesParallel(["x"], { onProgress: "not-fn" }),
    "opts.onProgress must be a function");
}

async function testUnknownAlgorithm() {
  var dir = _scratch("badalg");
  try {
    var p = _writeBytes(dir, "a.bin", 8);
    var threw = null;
    try { await b.crypto.hashFilesParallel([p], { algorithms: ["sha-bogus"] }); }
    catch (e) { threw = e; }
    check("unknown algorithm rejected", threw && /unknown algorithm/.test(threw.message));
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

async function testMissingFile() {
  var threw = null;
  try { await b.crypto.hashFilesParallel(["/no-such-file-12345"]); }
  catch (e) { threw = e; }
  check("missing file rejected", threw !== null);
}

async function run() {
  testSurface();
  await testHappyPath();
  await testOrderPreserved();
  await testCustomAlgorithms();
  await testProgressCallback();
  await testProgressCallbackErrorsSwallowed();
  await testEmptyArray();
  await testBadInputs();
  await testUnknownAlgorithm();
  await testMissingFile();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
