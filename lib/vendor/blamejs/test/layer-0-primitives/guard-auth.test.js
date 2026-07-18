// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// A well-formed structural JWT (ES256 header, future exp/iat/iss) — passes
// guardJwt's structural validation. Not a real signature; validate is a
// pure inspection of shape, not a cryptographic verify.
var BENIGN_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJpc3MiOiJleGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9.sig";

// alg=none JWT — RFC 7518 §3.6 explicit-no-signature, the canonical
// bearer-token forgery class guardAuth advertises routing through guardJwt.
var ALG_NONE_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.";

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

function testValidate() {
  // Benign bundle (bearer token + cookie header) is clean under balanced.
  var okRv = b.guardAuth.validate(
    { jwtToken: BENIGN_JWT, cookieHeader: "sid=abc123; theme=dark" },
    { profile: "balanced" });
  check("guardAuth.validate benign ok",             okRv.ok === true);
  check("guardAuth.validate benign no issues",      okRv.issues.length === 0);

  // Hostile: alg=none token routed to guardJwt, tagged source="jwt".
  var jwtRv = b.guardAuth.validate({ jwtToken: ALG_NONE_JWT }, { profile: "strict" });
  check("guardAuth.validate alg=none refused",      jwtRv.ok === false);
  check("guardAuth.validate alg=none source=jwt",
    jwtRv.issues.some(function (i) { return i.source === "jwt"; }));
  check("guardAuth.validate alg=none alg-none rule",
    jwtRv.issues.some(function (i) { return i.ruleId === "jwt.alg-none"; }));

  // Strict requireAtLeastOne — an empty bundle is refused so an operator
  // can't wire a gate onto a credential-less request.
  var emptyRv = b.guardAuth.validate({}, { profile: "strict" });
  check("guardAuth.validate empty strict refused",  emptyRv.ok === false);
  check("guardAuth.validate empty no-auth-input",
    emptyRv.issues.some(function (i) { return i.ruleId === "auth.no-auth-input"; }));

  // CL+TE request-header smuggling (RFC 9112 §6.1), source="headers".
  var smugRv = b.guardAuth.validate(
    { requestHeaders: { "content-length": "10", "transfer-encoding": "chunked" } },
    { profile: "strict" });
  check("guardAuth.validate smuggling refused",     smugRv.ok === false);
  check("guardAuth.validate smuggling source=headers",
    smugRv.issues.some(function (i) {
      return i.source === "headers" && i.ruleId === "auth.header-smuggling-cl-te";
    }));
}

function testSanitize() {
  // Clean bundle passes through unchanged (identity transform), and the
  // returned bundle re-validates clean.
  var input = { jwtToken: BENIGN_JWT, cookieHeader: "sid=abc123; theme=dark" };
  var clean = b.guardAuth.sanitize(input, { profile: "balanced" });
  check("guardAuth.sanitize benign returns bundle", clean === input);
  check("guardAuth.sanitize benign revalidates ok",
    b.guardAuth.validate(clean, { profile: "balanced" }).ok === true);

  // Hostile: a CL+TE smuggling bundle is REFUSED (thrown), never returned —
  // the auth bundle can't be repaired in transit, so neutralization is
  // refusal, not a silently-mutated pass-through.
  var attack = { requestHeaders: { "content-length": "10", "transfer-encoding": "chunked" } };
  var err = expectThrows("guardAuth.sanitize smuggling throws",
    function () { b.guardAuth.sanitize(attack, { profile: "strict" }); },
    "auth.header-smuggling-cl-te");
  check("guardAuth.sanitize smuggling GuardAuthError",
    err instanceof b.guardAuth.GuardAuthError);

  // Hostile: alg=none bearer token refuses at sanitize too.
  expectThrows("guardAuth.sanitize alg=none throws",
    function () { b.guardAuth.sanitize({ jwtToken: ALG_NONE_JWT }, { profile: "strict" }); },
    "jwt.alg-none");
}

async function testGate() {
  var authGate = b.guardAuth.gate({ profile: "strict" });

  // Hostile alg=none bundle → refuse.
  var refuse = await authGate.check({ authBundle: { jwtToken: ALG_NONE_JWT } });
  check("guardAuth.gate alg=none action=refuse",    refuse.action === "refuse");
  check("guardAuth.gate alg=none ok=false",         refuse.ok === false);
  check("guardAuth.gate alg=none issue source=jwt",
    refuse.issues.some(function (i) { return i.source === "jwt"; }));

  // Benign bearer token → serve.
  var serve = await authGate.check({ authBundle: { jwtToken: BENIGN_JWT } });
  check("guardAuth.gate benign action=serve",       serve.action === "serve");
  check("guardAuth.gate benign ok=true",            serve.ok === true);

  // No bundle on ctx → serve (nothing to gate; other middleware owns the
  // absent-credential decision).
  var none = await authGate.check({});
  check("guardAuth.gate no-bundle action=serve",    none.action === "serve");
}

async function run() {
  testValidate();
  testSanitize();
  await testGate();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
