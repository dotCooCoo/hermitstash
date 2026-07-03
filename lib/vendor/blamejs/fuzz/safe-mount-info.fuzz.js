// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.safeMountInfo.parse
 *
 * Feeds adversarial bytes through the canonical mountinfo parser
 * to catch shapes that produce uncaught error classes outside the
 * documented refusal surface (parse-failed / too-many-lines / bad-
 * input). The parser MUST survive every byte sequence — kernel-
 * published mountinfo can be malformed during concurrent mount /
 * unmount, and a hostile container probe could publish arbitrary
 * bytes via a writable /proc bind.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  if (!Buffer.isBuffer(data) || data.length === 0) return;
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  // Vary strict-mode + maxLines based on a per-corpus byte so fuzzer
  // gets coverage of both arms.
  var strict   = (data[0] & 0x01) === 1;                                              // allow:raw-byte-literal — first-bit alternation
  var capByte  = data.length > 1 ? data[1] : 0;
  var maxLines = (capByte + 1) * 16;                                                   // allow:raw-byte-literal — 16..4096 line cap range
  try {
    b.safeMountInfo.parse(text, { strict: strict, maxLines: maxLines });
  } catch (e) {
    if (expected.isExpected(e)) return;
    throw e;
  }
};
