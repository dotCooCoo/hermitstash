// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.guardListId.validate
 *
 * Targets the RFC 2919 List-Id parser: refuses CRLF / NUL / C0 / DEL
 * header injection, malformed brackets, phrase smuggling, non-dot-
 * atom labels, oversize identifiers.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  try {
    b.guardListId.validate(data.toString("utf8"));
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("guard-list-id/") === 0) return;
    throw e;
  }
};
