// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.network.dns.dane (DANE / TLSA certificate matching).
 * The oracle is a REAL DNSSEC-signed TLSA record for dane.sys4.de plus
 * that server's actual leaf certificate (captured via `openssl s_client
 * -connect dane.sys4.de:443`): the SHA-256 of the certificate's
 * subjectPublicKeyInfo equals the record's association data, so a wrong
 * SPKI extraction or hash would fail this match.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

// Real `_443._tcp.dane.sys4.de` TLSA: usage 3 (DANE-EE), selector 1
// (SPKI), matching 1 (SHA-256).
var TLSA_DANE_EE = { usage: 3, selector: 1, matchingType: 1, data: "eb74fe41c51d2876a50f0fe95ba6441119a38597a177e1ba54d68acb9a91efa3" };
// dane.sys4.de's real leaf certificate (DER).
var CERT_HEX = "308205f1308204d9a0030201020212061d670ec5c40f0709b0eb3279dfbf4a0780300d06092a864886f70d01010b05003033310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303523133301e170d3236303430373232303134395a170d3236303730363232303134385a3017311530130603550403130c64616e652e737973342e646530820222300d06092a864886f70d01010105000382020f003082020a0282020100a1e920d22e53fcd7ea5d47fa4c8ad99701e47cbeca1a1d290c5c5bfaecec805d8248174a7561c5f7ee23b68f5e4561df143eeccc1e849d6ad3b49a60a294798131bf0704364fd230803c7327d7a82b7c4e87daabc5f5474781a56003c1f0c3ad03960475b2bcb93b2a998f53531c0bdac8a9ddd0fe064b9a19a18c1b7220456c530a27c1cb39253e14157d805b17e0866a80e866d00cbf2e0a2481b72f1a9db141e557594c5e93a26fbe6f3548cff8a7d0ca82a0e0771cafd539da8e9dc13c8ceb618891994010a9a1b91e6a0e41ada62b1ad5018e654e0dad0274a6c2c4567afd7b71575ff597223071b5e4c15474ed6c3ee39763f996bbc5d99b908e89ead08058a3a65f5fa6ed962e7a891eba1fe68464db135a076db758ebd7fc3e665aed18ffadddf2f9deb76c164b56f9a91ba852608b1d562512f56e8ed30cad51d4cd0208a6e563eaf7ec94dd6ab7cca8616ca1a9c9c116bf4dcaad8cc7691a69e6e054a8f227c35c80b2dbcd1c2ec042af00bf7b98a1b531736f0d44c94fab6906be1fbdb3b7eff9d1c212d3e139a8d0aef994504ea3f4fffb8a11cf17fcdf012545779621ee4302b123fcb5ee02cc1cfb8389cb99d764fe305bc7f87bd9611bc0ab02012bd1cee8e8eeef9f77d9fa91c911283468d79a03c3ba9a8b1377ef2fdf8fc4ffb4d27b0af8d24686aa260593600e962ec7dee76c259aad77b0ed06f59acd0203010001a382021930820215300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000301d0603551d0e0416041490d876e1363cedc1e8f840acea8a001831415abb301f0603551d23041830168014e7ab9f0f2c33a053d35e4f78c8b2840e3bd69233303306082b0601050507010104273025302306082b060105050730028617687474703a2f2f7231332e692e6c656e63722e6f72672f30170603551d110410300e820c64616e652e737973342e646530130603551d20040c300a3008060667810c010201302d0603551d1f042630243022a020a01e861c687474703a2f2f7231332e632e6c656e63722e6f72672f312e63726c3082010c060a2b06010401d6790204020481fd0481fa00f8007600d76d7d10d1a7f577c2c7e95fd700bff982c9335a65e1d0b3017317c0c8c569770000019d6a2ce2560000040300473045022100997e2a727dd924aa0ee78fad453a1822e3c4739c7bef6d8c4fead20f6ac99dd502200a744a3f55fa27f1f6d23b25d857676a34468a9c0df525c6313e6308907d7860007e00a826cbe30ac6351246533fe065f14f19d96e190813c41dd96d7900b3123c55270000019d6a2ce5920008000005000604e6ca040300473045022100b180e6e36983a8c109a115b948a5efa5f0b1f1a135cf961caafefbd69e38d64a022010e833f73d2c8f9069170c3803bb5bbab0f5ffd4e00b4ef0bc599bba59f7a9e2300d06092a864886f70d01010b050003820101006f7523afa8550ff4ee625ce6fd892b3a76584af142f53829b9976b4ffe4f0c8d3dab67a8298b17d0e3bad9f93c831832bfd60a9b7609eb1cd414e91ee094e633b972c2858b07dee4efdfccf5909d51fc2234229b783ab7fa598e9579aa3fd1089df4f3a33840ae6ed75ac27ad4645f2b87a32adc9a62dade43b97955d1395ff2b9c3ac30967da3211d04dbb6b3a470021a9218600c6c1158854f4fc4673a50f0be9e137705ab44e9a4fa0bccc247d01e7fda67475b8471075b8bb7b72229817af1d3688f55607edd7a3cd8259470c8f4fe5faa7e184aeb15582dc8a3b82666b3502d8d39a9a1130bf06ef82a072c84a432f016fb1d555bebaa4533d8b432ddba";

function cert() { return Buffer.from(CERT_HEX, "hex"); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testSurface() {
  check("b.network.dns.dane.matchCertificate is a function", typeof b.network.dns.dane.matchCertificate === "function");
  check("b.network.dns.dane.USAGES maps 3 to DANE-EE", b.network.dns.dane.USAGES[3] === "DANE-EE");
}

function testRealVector() {
  var out = b.network.dns.dane.matchCertificate({ tlsa: [TLSA_DANE_EE], certificate: cert() });
  check("matchCertificate: real dane.sys4.de DANE-EE TLSA matches the real cert (SPKI/SHA-256)", out.ok && out.matched.usage === 3);
  check("matchCertificate: DANE-EE is self-authenticating (no PKIX required)", out.daneAuthenticated === true && out.pkixRequired === false);

  // The same cert matched by a full-cert (selector 0) exact (matching 0)
  // record — derive the association from the cert DER itself.
  var full = { usage: 3, selector: 0, matchingType: 0, data: cert() };
  var out2 = b.network.dns.dane.matchCertificate({ tlsa: [full], certificate: cert() });
  check("matchCertificate: full-cert exact selector matches", out2.ok && out2.matched.selector === 0 && out2.matched.matchingType === 0);
}

function testRefusals() {
  // A flipped association byte no longer matches.
  var bad = { usage: 3, selector: 1, matchingType: 1, data: TLSA_DANE_EE.data.replace(/^eb/, "ec") };
  check("matchCertificate: wrong association refused", code(function () { b.network.dns.dane.matchCertificate({ tlsa: [bad], certificate: cert() }); }) === "dane/no-match");
  // Unknown usage / selector / matching are refused, not guessed.
  check("matchCertificate: unsupported usage refused", code(function () { b.network.dns.dane.matchCertificate({ tlsa: [{ usage: 9, selector: 1, matchingType: 1, data: TLSA_DANE_EE.data }], certificate: cert() }); }) === "dane/unsupported-usage");
  check("matchCertificate: unsupported selector refused", code(function () { b.network.dns.dane.matchCertificate({ tlsa: [{ usage: 3, selector: 9, matchingType: 1, data: TLSA_DANE_EE.data }], certificate: cert() }); }) === "dane/unsupported-selector");
  check("matchCertificate: unsupported matching type (e.g. SHA-1) refused", code(function () { b.network.dns.dane.matchCertificate({ tlsa: [{ usage: 3, selector: 1, matchingType: 3, data: TLSA_DANE_EE.data }], certificate: cert() }); }) === "dane/unsupported-matching");
  // Garbage certificate refused.
  check("matchCertificate: bad certificate refused", code(function () { b.network.dns.dane.matchCertificate({ tlsa: [TLSA_DANE_EE], certificate: Buffer.from("not a cert") }); }) === "dane/bad-certificate");
  // Empty TLSA set refused.
  check("matchCertificate: empty TLSA set refused", code(function () { b.network.dns.dane.matchCertificate({ tlsa: [], certificate: cert() }); }) === "dane/bad-arg");
  // String enum values are refused (they coerce on key lookup but break
  // the strict-=== usage logic), not silently accepted.
  check("matchCertificate: string usage refused", code(function () { b.network.dns.dane.matchCertificate({ tlsa: [{ usage: "3", selector: 1, matchingType: 1, data: TLSA_DANE_EE.data }], certificate: cert() }); }) === "dane/unsupported-usage");
  // Prototype-chain keys must not slip past the enum check.
  check("matchCertificate: __proto__ matchingType refused", code(function () { b.network.dns.dane.matchCertificate({ tlsa: [{ usage: 3, selector: 1, matchingType: "__proto__", data: TLSA_DANE_EE.data }], certificate: cert() }); }) === "dane/unsupported-matching");
  check("matchCertificate: __proto__ selector refused", code(function () { b.network.dns.dane.matchCertificate({ tlsa: [{ usage: 3, selector: "__proto__", matchingType: 1, data: TLSA_DANE_EE.data }], certificate: cert() }); }) === "dane/unsupported-selector");
}

function testPkixUsage() {
  // A PKIX-EE(1) match flags that PKIX validation is still required.
  var pkixEe = { usage: 1, selector: 1, matchingType: 1, data: TLSA_DANE_EE.data };
  var out = b.network.dns.dane.matchCertificate({ tlsa: [pkixEe], certificate: cert() });
  check("matchCertificate: PKIX-EE match flags pkixRequired", out.ok && out.matched.usage === 1 && out.pkixRequired === true && out.daneAuthenticated === false);
}

async function run() {
  testSurface();
  testRealVector();
  testRefusals();
  testPkixUsage();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[dane] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
