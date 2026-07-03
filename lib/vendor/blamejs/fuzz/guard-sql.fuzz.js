// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.guardSql (validate / sanitize)
 *
 * Targets the raw-SQL guard's tokenizer-first contract: the encoding
 * gate (string / Buffer-or-refuse), the comment-strip + literal-mask
 * normalizer, and the injection / exfil / OS-reach detector pipeline.
 *
 * validate() must NEVER throw on arbitrary bytes - it classifies and
 * returns { ok, issues }; any throw out of it is a finding. sanitize()
 * refuses unrepairable input with GuardSqlError (code prefix "sql.").
 */

var b        = require("..");
var expected = require("./_expected");

function expectedRefusal(e) {
  if (expected.isExpected(e)) return true;
  if (e && typeof e.code === "string" && e.code.indexOf("sql.") === 0) return true;
  return false;
}

module.exports.fuzz = function (data) {
  // No-throw classification contract (default + strict profiles).
  b.guardSql.validate(data);
  b.guardSql.validate(data, { profile: "strict" });

  // Refusal path: sanitize throws GuardSqlError on hostile / unrepairable
  // input; anything else is an unexpected crash.
  try {
    b.guardSql.sanitize(data);
  } catch (e) {
    if (expectedRefusal(e)) return;
    throw e;
  }
};
