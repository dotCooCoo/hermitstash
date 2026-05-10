"use strict";
/**
 * b.safeUrl.parse — IDN homograph mixed-script refusal (UTS #39 §5).
 *
 * Cyrillic-inside-Latin host labels (the gооgle.com / xn--ggle-55da.com
 * shape) refuse by default; operators with legitimate non-Latin hosts
 * opt in via allowMixedScript: true OR allowedScripts: [...].
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testMixedScriptRefused() {
  // xn--ggle-55da.com decodes to 'gооgle.com' where the two 'о' are
  // U+043E (Cyrillic) inside an otherwise-Latin label.
  var threw = false;
  var err;
  try { b.safeUrl.parse("https://xn--ggle-55da.com/foo"); }
  catch (e) { threw = true; err = e; }
  check("mixed-script (Cyrillic+Latin) host refused by default",
        threw && err && err.code === "safe-url/idn-homograph");
}

function testPureLatinPasses() {
  var u = b.safeUrl.parse("https://google.com/foo");
  check("pure-Latin host parses",
        u && u.hostname === "google.com");
}

function testPureCyrillicPasses() {
  // xn--80akhbyknj4f.com — every label codepoint Cyrillic
  var u = b.safeUrl.parse("https://xn--80akhbyknj4f.com/");
  check("pure-Cyrillic host parses (single-script)",
        u && u.hostname === "xn--80akhbyknj4f.com");
}

function testAllowMixedScriptOptIn() {
  var u = b.safeUrl.parse("https://xn--ggle-55da.com/", {
    allowMixedScript: true,
  });
  check("allowMixedScript:true accepts mixed-script host",
        u && u.hostname === "xn--ggle-55da.com");
}

function testAllowedScriptsAcceptsListed() {
  // Mixing latin + cyrillic explicitly allowlisted -> passes
  var u = b.safeUrl.parse("https://xn--ggle-55da.com/", {
    allowedScripts: ["latin", "cyrillic"],
  });
  check("allowedScripts: ['latin','cyrillic'] accepts that mixture",
        u && u.hostname === "xn--ggle-55da.com");
}

function testAllowedScriptsRefusesUnlistedScript() {
  var threw = false;
  try { b.safeUrl.parse("https://xn--ggle-55da.com/", { allowedScripts: ["latin"] }); }
  catch (_e) { threw = true; }
  check("allowedScripts: ['latin'] still refuses Cyrillic-inside-Latin",
        threw === true);
}

async function run() {
  testMixedScriptRefused();
  testPureLatinPasses();
  testPureCyrillicPasses();
  testAllowMixedScriptOptIn();
  testAllowedScriptsAcceptsListed();
  testAllowedScriptsRefusesUnlistedScript();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
