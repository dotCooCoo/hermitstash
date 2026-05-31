"use strict";
/**
 * b.mail.srs — Sender Rewriting Scheme (SRS0).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _newSrs(opts) {
  return b.mail.srs.create(Object.assign({
    secret:          b.crypto.generateToken(32),
    forwarderDomain: "forwarder.example",
  }, opts || {}));
}

function testSurface() {
  check("mail.srs.create is fn", typeof b.mail.srs.create === "function");
  check("mail.srs.SrsError is a constructor",
        typeof b.mail.srs.SrsError === "function");
}

function testRoundTrip() {
  var srs = _newSrs();
  var rw = srs.rewrite("alice@bob.com");
  check("rewrite: starts with SRS0=", rw.startsWith("SRS0="));
  check("rewrite: ends with @forwarder.example",
        rw.endsWith("@forwarder.example"));
  check("reverse: round-trip recovers original",
        srs.reverse(rw) === "alice@bob.com");
}

function testTagTampering() {
  var srs = _newSrs();
  var rw = srs.rewrite("alice@bob.com");
  // Tamper the 4-char tag immediately after "SRS0=" — flip a char.
  var tampered = "SRS0=ZZZZ=" + rw.slice(10);
  var threw = null;
  try { srs.reverse(tampered); } catch (e) { threw = e; }
  check("reverse: tampered tag refused",
        threw && /srs\/bad-tag/.test(threw.code || ""));
}

function testSecretDivergence() {
  var srs1 = _newSrs();
  var srs2 = _newSrs();  // different secret
  var rw = srs1.rewrite("alice@bob.com");
  var threw = null;
  try { srs2.reverse(rw); } catch (e) { threw = e; }
  check("reverse: different secret refuses",
        threw && /srs\/bad-tag/.test(threw.code || ""));
}

function testExpiry() {
  var srs = b.mail.srs.create({
    secret:          b.crypto.generateToken(32),
    forwarderDomain: "forwarder.example",
    expiryDays:      30,
  });
  var pastMs = Date.now() - (40 * 86400000);                                                       // 40 days ago
  var rw = srs.rewrite("alice@bob.com", pastMs);
  var threw = null;
  try { srs.reverse(rw); } catch (e) { threw = e; }
  check("reverse: rewrites older than expiry refused",
        threw && /srs\/expired/.test(threw.code || ""));
}

function testBadShape() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("create: missing opts",
             function () { b.mail.srs.create(); }, "srs/bad-opts");
  expectCode("create: short secret",
             function () { b.mail.srs.create({ secret: "abc", forwarderDomain: "x.com" }); }, "srs/bad-secret");
  expectCode("create: bad expiryDays",
             function () { b.mail.srs.create({ secret: b.crypto.generateToken(32), forwarderDomain: "x.com", expiryDays: 0 }); }, "srs/bad-expiry");

  var srs = _newSrs();
  expectCode("rewrite: empty address",
             function () { srs.rewrite(""); }, "srs/bad-address");
  expectCode("rewrite: no @",
             function () { srs.rewrite("notanemail"); }, "srs/bad-address");
  expectCode("rewrite: already SRS-encoded",
             function () { srs.rewrite("SRS0=abc=de=bob.com=alice@forwarder.example"); }, "srs/already-rewritten");
  expectCode("reverse: not SRS0",
             function () { srs.reverse("plain@example.com"); }, "srs/not-srs0");
  expectCode("reverse: malformed",
             function () { srs.reverse("SRS0=abc@forwarder.example"); }, "srs/malformed");
}

function testForwarderDomainBinding() {
  // create({ forwarderDomain }) binds the rewriter to a specific
  // forwarder. reverse() must refuse bounces addressed to a
  // DIFFERENT domain even when the SRS0 local-part is otherwise
  // signed by the same secret — otherwise multi-domain handlers
  // can mis-deliver bounces.
  var secret = b.crypto.generateToken(32);
  var srs1 = b.mail.srs.create({ secret: secret, forwarderDomain: "fwd1.example" });
  var srs2 = b.mail.srs.create({ secret: secret, forwarderDomain: "fwd2.example" });

  var rw1 = srs1.rewrite("alice@bob.com");
  check("rewrite: ends with bound forwarder domain",
        rw1.endsWith("@fwd1.example"));

  // Use the same secret on srs2 — same HMAC tag verifies.
  var threw = null;
  try { srs2.reverse(rw1); } catch (e) { threw = e; }
  check("reverse: bounce addressed to wrong forwarder refused",
        threw && /srs\/wrong-forwarder/.test(threw.code || ""));

  // Same forwarder, different case — RFC 5321 §2.3.5 says domains
  // are case-insensitive, so reverse() must accept the bounce.
  var srsUpper = b.mail.srs.create({ secret: secret, forwarderDomain: "FWD1.example" });
  check("reverse: case-insensitive domain match",
        srsUpper.reverse(rw1) === "alice@bob.com");

  // Empty local-part / no domain refused.
  var threw2 = null;
  try { srs1.reverse("SRS0=abc=de=bob.com=alice@"); } catch (e) { threw2 = e; }
  check("reverse: empty domain refused",
        threw2 && /srs\/bad-address/.test(threw2.code || ""));
}

function testLocalPartWithEquals() {
  // Some local-parts can contain "=" in RFC 5321; SRS reverse should
  // recover the full original local-part by re-joining slice(3).
  var srs = _newSrs();
  var rw = srs.rewrite("foo=bar@bob.com");
  check("reverse: local-part with '=' survives round-trip",
        srs.reverse(rw) === "foo=bar@bob.com");
}

function testSrs1DoubleForward() {
  // Two distinct forwarders with distinct secrets.
  var srsA = b.mail.srs.create({ secret: b.crypto.generateToken(32), forwarderDomain: "fwd1.example" });
  var srsB = b.mail.srs.create({ secret: b.crypto.generateToken(32), forwarderDomain: "fwd2.example" });

  // Hop 1: alice@bob.com → fwd1 (SRS0).
  var rw0 = srsA.rewrite("alice@bob.com");
  check("srs1: first hop is SRS0 at fwd1", rw0.startsWith("SRS0=") && rw0.endsWith("@fwd1.example"));

  // Hop 2: fwd2 chains the already-SRS0 address as SRS1.
  var rw1 = srsB.srs1Rewrite(rw0);
  check("srs1: produces SRS1=",                rw1.startsWith("SRS1="));
  check("srs1: ends at this forwarder (fwd2)", rw1.endsWith("@fwd2.example"));
  check("srs1: embeds the SRS0 originator",    rw1.indexOf("fwd1.example") !== -1);
  check("srs1: has '==' separator",            rw1.indexOf("==") > 0);

  // reverse() at fwd2 unwraps exactly one hop → the originator's SRS0 (== rw0).
  var back = srsB.reverse(rw1);
  check("srs1: reverse unwraps one hop to the originator SRS0", back === rw0);
  // fwd1 then reverses that SRS0 → original sender (full chain).
  check("srs1: two-hop chain recovers the original sender", srsA.reverse(back) === "alice@bob.com");

  // Tampered SRS1 tag → bad-tag.
  var tampered = "SRS1=ZZZZ=" + rw1.slice(rw1.indexOf("=", 5) + 1);
  var threwTag = null;
  try { srsB.reverse(tampered); } catch (e) { threwTag = e; }
  check("srs1: tampered tag refused", threwTag && /srs\/bad-tag/.test(threwTag.code || ""));

  // rw1 is addressed to fwd2; fwd1 reversing it → wrong-forwarder.
  var threwFwd = null;
  try { srsA.reverse(rw1); } catch (e) { threwFwd = e; }
  check("srs1: bounce at the wrong forwarder refused", threwFwd && /srs\/wrong-forwarder/.test(threwFwd.code || ""));

  // srs1Rewrite on a plain (non-SRS) address → not-srs0.
  var threwPlain = null;
  try { srsB.srs1Rewrite("alice@bob.com"); } catch (e) { threwPlain = e; }
  check("srs1Rewrite: plain address refused", threwPlain && /srs\/not-srs0/.test(threwPlain.code || ""));

  // srs1Rewrite empty / no-@ → bad-address.
  var threwEmpty = null;
  try { srsB.srs1Rewrite(""); } catch (e) { threwEmpty = e; }
  check("srs1Rewrite: empty refused", threwEmpty && /srs\/bad-address/.test(threwEmpty.code || ""));

  // reverse of a malformed SRS1 (no '==' separator) → malformed.
  var threwMal = null;
  try { srsB.reverse("SRS1=abc@fwd2.example"); } catch (e) { threwMal = e; }
  check("srs1: malformed (no '==') refused", threwMal && /srs\/malformed/.test(threwMal.code || ""));

  // Third hop: fwd3 re-wraps fwd2's SRS1. The bounce target stays the
  // SRS0 originator (fwd1), so it still routes straight back, never to
  // the intermediate fwd2.
  var srsC = b.mail.srs.create({ secret: b.crypto.generateToken(32), forwarderDomain: "fwd3.example" });
  var rw2 = srsC.srs1Rewrite(rw1);
  check("srs1: third hop is SRS1 at fwd3",                rw2.startsWith("SRS1=") && rw2.endsWith("@fwd3.example"));
  check("srs1: third hop keeps the originator (fwd1)",    rw2.indexOf("fwd1.example") !== -1);
  var back2 = srsC.reverse(rw2);
  check("srs1: third hop unwraps straight back to the originator SRS0", back2 === rw0);
  check("srs1: full three-hop chain recovers the original sender",      srsA.reverse(back2) === "alice@bob.com");
}

async function run() {
  testSurface();
  testRoundTrip();
  testTagTampering();
  testSecretDivergence();
  testExpiry();
  testBadShape();
  testForwarderDomainBinding();
  testLocalPartWithEquals();
  testSrs1DoubleForward();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
