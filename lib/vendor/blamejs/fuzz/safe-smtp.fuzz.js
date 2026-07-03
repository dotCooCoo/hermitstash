// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.mail.server.mx wire-protocol layer.
 *
 * Targets the three byte-scan helpers that defend SMTP smuggling
 * (CVE-2023-51764 / CVE-2024-32178) and the RFC 5321 §4.5.2 dot-
 * stuffing reversal. Operator-supplied byte input drives the SMTP
 * server's DATA-body ingestion; the engine mutates these bytes to
 * find shapes the detectors miss OR shapes the detectors flag
 * spuriously.
 *
 * libFuzzer / jazzer.js harness; ClusterFuzzLite consumes this shape.
 *
 * Expected behavior:
 *   - _detectSmugglingShape returns boolean; never throws.
 *   - _findDotTerminator returns -1 or a valid byte index in [0, buf.length].
 *   - _dotUnstuff returns a Buffer of length <= input length; never throws.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  // Skip empty + huge inputs — libFuzzer mutates length too.
  if (data.length === 0 || data.length > 1 * 1024 * 1024) return;

  try {
    // 1. guardSmtpCommand.detectBodySmuggling — must return boolean.
    var smuggling = b.guardSmtpCommand.detectBodySmuggling(data);
    if (typeof smuggling !== "boolean") {
      throw new Error("detectBodySmuggling returned non-boolean: " + typeof smuggling);
    }

    // 2. safeSmtp.findDotTerminator — must return -1 OR an index in range.
    var endIdx = b.safeSmtp.findDotTerminator(data);
    if (typeof endIdx !== "number") {
      throw new Error("findDotTerminator returned non-number: " + typeof endIdx);
    }
    if (endIdx !== -1 && (endIdx < 0 || endIdx > data.length)) {
      throw new Error("findDotTerminator returned out-of-range index: " + endIdx);
    }
    // If a terminator was found, verify the 5-byte pattern actually
    // exists at the returned index (\r\n.\r\n).
    if (endIdx !== -1) {
      if (data[endIdx]     !== 0x0d || data[endIdx + 1] !== 0x0a ||
          data[endIdx + 2] !== 0x2e ||
          data[endIdx + 3] !== 0x0d || data[endIdx + 4] !== 0x0a) {
        throw new Error("findDotTerminator returned index without CRLF.CRLF: " + endIdx);
      }
    }

    // 3. safeSmtp.dotUnstuff — must return a Buffer; length never exceeds input.
    var unstuffed = b.safeSmtp.dotUnstuff(data);
    if (!Buffer.isBuffer(unstuffed)) {
      throw new Error("dotUnstuff returned non-Buffer: " + typeof unstuffed);
    }
    if (unstuffed.length > data.length) {
      throw new Error("dotUnstuff returned longer buffer: " + unstuffed.length + " > " + data.length);
    }
  } catch (e) {
    if (expected.isExpected(e)) return;
    throw e;
  }
};
