// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.safeIcap.parse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite + OSS-Fuzz consume
 * `module.exports.fuzz = function (data)` where `data` is a Buffer
 * the engine mutates. The parser MUST refuse every malformed shape
 * with a `safe-icap/<code>` error and never throw an internal
 * invariant break — operator-supplied ICAP bytes are untrusted.
 *
 * Targets the ICAP-response-injection + parser-bomb class:
 *   - Bare-CR / bare-LF / NUL in headers (smuggling)
 *   - Unexpected status codes (header-injection via 1xx continuation)
 *   - Oversize body (RFC 3507 §3 no wire-level cap → parser-bomb)
 *   - Encapsulated header malformed (panic or pathological offset)
 */

var safeIcap = require("../lib/safe-icap");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  if (data.length === 0 || data.length > 1 * 1024 * 1024) return;                                  // allow:raw-byte-literal — 1 MiB fuzz input cap
  try {
    var rv = safeIcap.parse(data);
    if (typeof rv !== "object" || rv === null) {
      throw new Error("parse returned non-object: " + typeof rv);
    }
    if (typeof rv.statusCode !== "number") {
      throw new Error("parse returned non-number statusCode");
    }
    if (!Object.prototype.hasOwnProperty.call(safeIcap.ALLOWED_STATUS, rv.statusCode)) {
      throw new Error("parse returned status outside allowlist: " + rv.statusCode);
    }
    if (typeof rv.threatFound !== "boolean") {
      throw new Error("parse returned non-boolean threatFound");
    }
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("safe-icap/") === 0) return;
    throw e;
  }
};
