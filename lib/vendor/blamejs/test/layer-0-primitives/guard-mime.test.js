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

function _kinds(rv) {
  return rv.issues.map(function (i) { return i.kind; });
}

function testValidate() {
  // Benign: a registered, well-formed media type is clean under strict.
  var okRv = b.guardMime.validate("application/json", { profile: "strict" });
  check("guardMime.validate benign ok",           okRv.ok === true);
  check("guardMime.validate benign no issues",    okRv.issues.length === 0);

  // Hostile: an executable/script-host media type is on the risky-type
  // refuse list — high severity under strict.
  var risky = b.guardMime.validate("application/x-msdownload", { profile: "strict" });
  check("guardMime.validate risky refused",       risky.ok === false);
  check("guardMime.validate risky-type kind",
    _kinds(risky).indexOf("risky-type") !== -1);

  // Hostile: missing `/` between type and subtype — mime-shape refuse.
  var shape = b.guardMime.validate("noslash", { profile: "strict" });
  check("guardMime.validate mime-shape refused",  shape.ok === false);
  check("guardMime.validate mime-shape kind",
    _kinds(shape).indexOf("mime-shape") !== -1);

  // Hostile: a space in the subtype violates the RFC 6838 restricted-
  // name grammar — subtype-shape refuse.
  var badTok = b.guardMime.validate("application/js on", { profile: "strict" });
  check("guardMime.validate subtype-shape refused", badTok.ok === false);
  check("guardMime.validate subtype-shape kind",
    _kinds(badTok).indexOf("subtype-shape") !== -1);

  // Wildcard is Accept-only — refused as a content-type at strict.
  var wild = b.guardMime.validate("*/*", { profile: "strict" });
  check("guardMime.validate wildcard refused",    wild.ok === false);
  check("guardMime.validate wildcard kind",
    _kinds(wild).indexOf("wildcard") !== -1);
}

function testSanitize() {
  // Benign: lower-cases the canonical type/subtype while preserving the
  // parameter value's case (boundary tokens are case-significant).
  var norm = b.guardMime.sanitize("Application/JSON; charset=UTF-8", { profile: "balanced" });
  check("guardMime.sanitize lowercases type/subtype",
    norm === "application/json; charset=UTF-8");
  check("guardMime.sanitize preserves param-value case",
    norm.indexOf("charset=UTF-8") !== -1);
  check("guardMime.sanitize output neutralized",
    norm !== "Application/JSON; charset=UTF-8");

  // Already-canonical input is returned unchanged under strict.
  var same = b.guardMime.sanitize("application/json", { profile: "strict" });
  check("guardMime.sanitize canonical unchanged",  same === "application/json");

  // Hostile: a script-host media type throws rather than normalizing a
  // risky type into place.
  var err = expectThrows("guardMime.sanitize risky-type throws",
    function () { b.guardMime.sanitize("application/javascript", { profile: "strict" }); },
    "mime.risky-type");
  check("guardMime.sanitize risky GuardMimeError",
    err instanceof b.guardMime.GuardMimeError);
}

async function run() {
  testValidate();
  testSanitize();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
