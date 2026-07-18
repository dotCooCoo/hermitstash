// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

function testSanitize() {
  // Benign: a plain RFC 9535 member/wildcard path carries no code-
  // execution shape — sanitize returns it byte-for-byte (JSONPath
  // strings can't be repaired, so the transform is pass-through).
  var safe = b.guardJsonpath.sanitize("$.users[*].name", { profile: "strict" });
  check("guardJsonpath.sanitize benign passthrough",  safe === "$.users[*].name");
  check("guardJsonpath.sanitize benign type",         typeof safe === "string");

  // Hostile: `?(...)` filter expression — the dynamic-code-execution
  // class in legacy JSONPath evaluators. Refused at every profile;
  // never returned as a "cleaned" string.
  var filterErr = expectThrows("guardJsonpath.sanitize filter-expression throws",
    function () { b.guardJsonpath.sanitize("$..[?(@.x)]", { profile: "strict" }); },
    "jsonpath.filter-expression");
  check("guardJsonpath.sanitize filter GuardJsonpathError",
    filterErr instanceof b.guardJsonpath.GuardJsonpathError);

  // Hostile: JS-source hint (dynamic-code-exec keyword) embedded in the
  // path — refused as a code-injection attempt.
  expectThrows("guardJsonpath.sanitize dynamic-hint throws",
    function () { b.guardJsonpath.sanitize("$[eval]", { profile: "strict" }); },
    "jsonpath.dynamic-hint");

  // Hostile: bare script-expression shape `(@.x)` — aliased to filter
  // in several implementations; refused under strict.
  expectThrows("guardJsonpath.sanitize script-expression throws",
    function () { b.guardJsonpath.sanitize("$[(@.length-1)]", { profile: "strict" }); },
    "jsonpath.script-expression");

  // Hostile: 3+ consecutive `[` — parser-DoS shape, high under strict.
  expectThrows("guardJsonpath.sanitize bracket-nesting throws",
    function () { b.guardJsonpath.sanitize("$[[[0]]]", { profile: "strict" }); },
    "jsonpath.bracket-nesting");

  // The RCE class is refused regardless of profile — a permissive
  // caller can loosen recursive-descent depth but never the filter/
  // script/dynamic-hint refusal.
  expectThrows("guardJsonpath.sanitize filter refused at permissive too",
    function () { b.guardJsonpath.sanitize("$..[?(@.x)]", { profile: "permissive" }); },
    "jsonpath.filter-expression");
}

async function run() {
  testSanitize();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
