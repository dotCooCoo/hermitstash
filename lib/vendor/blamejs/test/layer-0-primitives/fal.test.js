"use strict";
/**
 * b.auth.fal — NIST 800-63-4 Federation Assurance Level classifier.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("fal.fromAssertion is fn", typeof b.auth.fal.fromAssertion === "function");
  check("fal.requireFal is fn",    typeof b.auth.fal.requireFal === "function");
  check("fal.meets is fn",         typeof b.auth.fal.meets === "function");
  check("BANDS in order",
        b.auth.fal.BANDS.join(",") === "FAL1,FAL2,FAL3");
}

function testFromAssertion() {
  // FAL1 — bare front-channel bearer
  check("FAL1 (front + no replay)",
        b.auth.fal.fromAssertion({ channel: "front" }) === "FAL1");
  check("FAL1 (front + replay-protected, no encryption)",
        b.auth.fal.fromAssertion({ channel: "front", replayProtected: true }) === "FAL1");

  // FAL2 — back-channel with replay protection AND injection-protection
  // (NIST 800-63C-4 §5.2 — replay alone is FAL1; the back-channel must
  // also be encrypted-to-RP OR the transport itself authenticated via
  // mTLS / signed JWT). Pre-v0.9.x classification accepted plain
  // back-channel + replay as FAL2, which contradicted §5.2.
  check("FAL2 (back + replay + backChannelAuthenticated)",
        b.auth.fal.fromAssertion({
          channel: "back", replayProtected: true, backChannelAuthenticated: true,
        }) === "FAL2");
  check("FAL2 (back + replay + encrypted)",
        b.auth.fal.fromAssertion({
          channel: "back", encrypted: true, replayProtected: true,
        }) === "FAL2");
  // FAL2 — front-channel encrypted-to-RP + replay protection
  check("FAL2 (front encrypted + replay-protected)",
        b.auth.fal.fromAssertion({ channel: "front", encrypted: true, replayProtected: true }) === "FAL2");
  // AUTH-19 — back-channel + replay WITHOUT injection-protection is
  // FAL1, not FAL2 (closes the §5.2 gap).
  check("FAL1 (back + replay only — no injection-protection)",
        b.auth.fal.fromAssertion({ channel: "back", replayProtected: true }) === "FAL1");

  // FAL3 — Holder-of-Key with replay protection
  check("FAL3 (mTLS HoK + replay)",
        b.auth.fal.fromAssertion({ channel: "back", hokBinding: "mtls", replayProtected: true }) === "FAL3");
  check("FAL3 (DPoP HoK + replay)",
        b.auth.fal.fromAssertion({ channel: "back", hokBinding: "dpop", replayProtected: true }) === "FAL3");

  // Replay-protection missing — HoK alone downgrades to FAL1 (conservative)
  check("HoK alone without replay → FAL1",
        b.auth.fal.fromAssertion({ channel: "back", hokBinding: "mtls" }) === "FAL1");

  // Back-channel without replay → FAL1
  check("back-channel without replay → FAL1",
        b.auth.fal.fromAssertion({ channel: "back" }) === "FAL1");
}

function testBearerOnlyAlias() {
  // bearerOnly:true is the documented alias for hokBinding === null —
  // it forces the bearer path. With replay + injection-protection on a
  // back-channel it still classifies as FAL2 (not FAL3), proving no
  // proof-of-possession binding is applied.
  check("bearerOnly:true → no HoK (back + replay + bcAuth = FAL2)",
        b.auth.fal.fromAssertion({
          channel: "back", replayProtected: true,
          backChannelAuthenticated: true, bearerOnly: true,
        }) === "FAL2");
  // bearerOnly:true with mTLS even + replay must NOT reach FAL3 —
  // bearerOnly wins is a contradiction, so it's refused (config-time).
  var threw = null;
  try {
    b.auth.fal.fromAssertion({ channel: "back", hokBinding: "mtls",
      replayProtected: true, bearerOnly: true });
  } catch (e) { threw = e; }
  check("bearerOnly:true + hokBinding refused",
        threw && (threw.code || "").indexOf("auth/bad-fal-opts") !== -1);
  // bearerOnly:false is a no-op (hokBinding still honored → FAL3).
  check("bearerOnly:false is inert (mTLS + replay = FAL3)",
        b.auth.fal.fromAssertion({ channel: "back", hokBinding: "mtls",
          replayProtected: true, bearerOnly: false }) === "FAL3");
}

function testFromAssertionRefusesBadShape() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("no opts",        function () { b.auth.fal.fromAssertion(); }, "auth/bad-fal-opts");
  expectCode("bad channel",    function () { b.auth.fal.fromAssertion({ channel: "side" }); }, "auth/bad-fal-opts");
  expectCode("bad hokBinding", function () { b.auth.fal.fromAssertion({ channel: "back", hokBinding: "kerberos" }); }, "auth/bad-fal-opts");
}

function testMeets() {
  check("FAL3 meets FAL2",  b.auth.fal.meets("FAL3", "FAL2") === true);
  check("FAL3 meets FAL3",  b.auth.fal.meets("FAL3", "FAL3") === true);
  check("FAL1 does not meet FAL2",  b.auth.fal.meets("FAL1", "FAL2") === false);

  // Contract: invalid bands on EITHER side return false. The pre-
  // v0.8.88 implementation mapped unknown bands to rank 0 and
  // returned `1 >= 0 === true` / `0 >= 0 === true`, producing
  // false-positive authorization decisions for operators using
  // meets() directly.
  check("invalid actual → false",      b.auth.fal.meets("FALX", "FAL1") === false);
  check("invalid required → false",    b.auth.fal.meets("FAL1", "FALX") === false);
  check("both invalid → false",        b.auth.fal.meets("bad", "bad") === false);
  check("both invalid identical → false", b.auth.fal.meets("FALX", "FALX") === false);
  check("non-string actual → false",   b.auth.fal.meets(null, "FAL1") === false);
  check("non-string required → false", b.auth.fal.meets("FAL1", null) === false);
  check("both null → false",           b.auth.fal.meets(null, null) === false);
}

function testRequireFal() {
  var guard = b.auth.fal.requireFal("FAL2");
  check("guard: FAL2 passes",   guard("FAL2") === "FAL2");
  check("guard: FAL3 passes",   guard("FAL3") === "FAL3");
  var threw = null;
  try { guard("FAL1"); } catch (e) { threw = e; }
  check("guard: FAL1 refused",
        threw && /fal-insufficient/.test(threw.code || ""));
  var threw2 = null;
  try { b.auth.fal.requireFal("FALX"); } catch (e) { threw2 = e; }
  check("requireFal: bad minimum refused",
        threw2 && /bad-fal-band/.test(threw2.code || ""));
}

async function run() {
  testSurface();
  testFromAssertion();
  testBearerOnlyAlias();
  testFromAssertionRefusesBadShape();
  testMeets();
  testRequireFal();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
