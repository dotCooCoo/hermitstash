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

async function run() {
  testSurface();
  testRoundTrip();
  testTagTampering();
  testSecretDivergence();
  testExpiry();
  testBadShape();
  testForwarderDomainBinding();
  testLocalPartWithEquals();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
