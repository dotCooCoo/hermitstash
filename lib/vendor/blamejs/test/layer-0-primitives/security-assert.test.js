// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  check("security namespace present",        typeof b.security === "object");
  check("security.assertProduction is fn",   typeof b.security.assertProduction === "function");

  // ---- Default: no router, only posture asserts apply ----
  // Inject resolvers so the test isn't sensitive to whatever framework
  // state happens to be initialized.
  function _resolvers(vaultMode, dbAtRest, auditMode) {
    return {
      vault:        function () { return vaultMode; },
      dbAtRest:     function () { return dbAtRest; },
      auditSigning: function () { return auditMode; },
    };
  }

  // Production-clean posture passes.
  var prevNtp = process.env.BLAMEJS_NTP_STRICT;
  delete process.env.BLAMEJS_NTP_STRICT;
  var passThrew = null;
  try {
    await b.security.assertProduction({
      resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
    });
  } catch (e) { passThrew = e; }
  check("clean production posture: no throw",   passThrew === null);

  // Dev posture (plaintext vault) fails on the first assertion.
  var devThrew = null;
  try {
    await b.security.assertProduction({
      resolvers: _resolvers("plaintext", "encrypted", "wrapped"),
    });
  } catch (e) { devThrew = e; }
  check("plaintext vault: throws SecurityAssertError",
        devThrew && devThrew.isSecurityAssertError === true);
  check("plaintext vault: failures array",       Array.isArray(devThrew.failures) && devThrew.failures.length === 1);
  check("plaintext vault: code mentions vault",  /vault/.test(devThrew.failures[0].code));

  // Multiple failures aggregate.
  var multiThrew = null;
  try {
    await b.security.assertProduction({
      resolvers: _resolvers("plaintext", "plain", "plaintext"),
    });
  } catch (e) { multiThrew = e; }
  check("triple failure: 3 failures aggregated", multiThrew && multiThrew.failures.length === 3);

  // BLAMEJS_NTP_STRICT=0 fails when ntpStrict assertion is on (default).
  process.env.BLAMEJS_NTP_STRICT = "0";
  var ntpThrew = null;
  try {
    await b.security.assertProduction({
      resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
    });
  } catch (e) { ntpThrew = e; }
  check("BLAMEJS_NTP_STRICT=0: throws",          ntpThrew !== null);
  check("BLAMEJS_NTP_STRICT=0: code references ntp",
        ntpThrew && /ntp/.test(ntpThrew.failures[0].code));
  if (prevNtp === undefined) delete process.env.BLAMEJS_NTP_STRICT;
  else process.env.BLAMEJS_NTP_STRICT = prevNtp;

  // Operator extra: passes
  var extraOk = null;
  try {
    await b.security.assertProduction({
      resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
      extra: [function () { return { ok: true }; }],
    });
  } catch (e) { extraOk = e; }
  check("extra:[ok] does not throw",              extraOk === null);

  // Operator extra: fails
  var extraFail = null;
  try {
    await b.security.assertProduction({
      resolvers: _resolvers("wrapped", "encrypted", "wrapped"),
      extra: [function () { return { ok: false, code: "wiki/x", message: "missing" }; }],
    });
  } catch (e) { extraFail = e; }
  check("extra:[fail] throws aggregated",         extraFail && extraFail.failures.length === 1);
  check("extra:[fail] preserves code",            extraFail.failures[0].code === "wiki/x");

  // Operator can opt out of an assertion (vault: false)
  var optOut = null;
  try {
    await b.security.assertProduction({
      vault: false,
      resolvers: _resolvers("plaintext", "encrypted", "wrapped"),
    });
  } catch (e) { optOut = e; }
  check("vault:false opts out of plaintext check", optOut === null);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[security-assert] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
