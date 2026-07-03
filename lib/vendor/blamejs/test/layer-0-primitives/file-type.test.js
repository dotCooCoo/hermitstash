// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function _png()  { return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), Buffer.alloc(20)]); }
function _jpeg() { return Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), Buffer.alloc(20)]); }
function _pdf()  { return Buffer.concat([Buffer.from("%PDF-1.7\n", "ascii"),  Buffer.alloc(20)]); }
function _gz()   { return Buffer.concat([Buffer.from([0x1F, 0x8B]), Buffer.alloc(20)]); }
function _pe()   { return Buffer.concat([Buffer.from([0x4D, 0x5A]), Buffer.alloc(20)]); }
function _elf()  { return Buffer.concat([Buffer.from([0x7F, 0x45, 0x4C, 0x46]), Buffer.alloc(20)]); }
function _polyglot() {
  // PNG header followed by what an attacker might claim is HTML.
  // Magic-byte check should still classify as PNG (the actual format).
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    Buffer.from("<script>alert(1)</script>", "utf8")]);
}

async function run() {
  check("fileType namespace present",                typeof b.fileType === "object");
  check("fileType.detect is fn",                     typeof b.fileType.detect === "function");
  check("fileType.assertOneOf is fn",                typeof b.fileType.assertOneOf === "function");

  // ---- Detection round-trips ----
  var pngDet = b.fileType.detect(_png());
  check("detect: PNG",                pngDet && pngDet.mime === "image/png" && pngDet.category === "image");
  var jpegDet = b.fileType.detect(_jpeg());
  check("detect: JPEG",               jpegDet && jpegDet.mime === "image/jpeg");
  var pdfDet = b.fileType.detect(_pdf());
  check("detect: PDF",                pdfDet && pdfDet.mime === "application/pdf" && pdfDet.category === "document");
  var gzDet = b.fileType.detect(_gz());
  check("detect: gzip",               gzDet && gzDet.category === "archive");
  var peDet = b.fileType.detect(_pe());
  check("detect: PE/Windows exe",     peDet && peDet.category === "executable");
  var elfDet = b.fileType.detect(_elf());
  check("detect: ELF",                elfDet && elfDet.category === "executable");

  // ---- Polyglot defense ----
  var poly = b.fileType.detect(_polyglot());
  check("detect: polyglot still PNG", poly && poly.mime === "image/png");

  // ---- assertOneOf happy path ----
  var ok = b.fileType.assertOneOf(_png(), ["image/png", "image/jpeg"]);
  check("assertOneOf: PNG passes",    ok && ok.mime === "image/png");
  var imgCat = b.fileType.assertOneOf(_jpeg(), ["image"]);
  check("assertOneOf: category match", imgCat && imgCat.mime === "image/jpeg");

  // ---- assertOneOf rejection ----
  var threwExe = null;
  try { b.fileType.assertOneOf(_pe(), ["image/png", "application/pdf"]); }
  catch (e) { threwExe = e; }
  check("assertOneOf: PE rejected",   threwExe && /DISALLOWED_TYPE/.test(threwExe.code || ""));

  var threwUnknown = null;
  try { b.fileType.assertOneOf(Buffer.from("not-a-real-format-bytes"), ["image/png"]); }
  catch (e) { threwUnknown = e; }
  check("assertOneOf: unknown format", threwUnknown && /UNKNOWN_TYPE/.test(threwUnknown.code || ""));

  var threwEmpty = null;
  try { b.fileType.assertOneOf(Buffer.alloc(0), ["image/png"]); }
  catch (e) { threwEmpty = e; }
  check("assertOneOf: zero-byte rejected by default", threwEmpty && /EMPTY/.test(threwEmpty.code || ""));

  var allowEmpty = b.fileType.assertOneOf(Buffer.alloc(0), ["image/png"], { allowEmpty: true });
  check("assertOneOf: zero-byte allowed when opted in", allowEmpty === null);

  // ---- detect() returns null for non-buffers and unrecognised content ----
  check("detect: null for non-buffer",  b.fileType.detect("not a buffer") === null);
  check("detect: null for empty",       b.fileType.detect(Buffer.alloc(0)) === null);
  check("detect: null for unknown",     b.fileType.detect(Buffer.from("not-a-real-format-bytes")) === null);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[file-type] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
