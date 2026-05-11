"use strict";
/**
 * b.auth.oauth callback / JARM / refresh-rotation primitives (v0.8.70):
 *   - parseCallback   (RFC 9207 AS Issuer Identifier validation)
 *   - parseJarmResponse (OAuth 2.0 JARM signed authorization response)
 *   - refreshAccessToken seen() callback (RFC 9700 §4.13 / OAuth 2.1 §6.1)
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

async function run() {
  var oauth = b.auth.oauth.create({
    issuer:        "https://idp.example",
    clientId:      "rp-1",
    clientSecret:  "test-secret",
    redirectUri:   "https://rp.example/cb",
    scope:         ["openid"],
    isOidc:        true,
    allowHttp:     true,
    allowInternal: true,
  });

  var rv = await oauth.parseCallback({ code: "abc123", state: "s1", iss: "https://idp.example" }, { expectedState: "s1" });
  check("oauth.parseCallback: happy path returns code+state",     rv.code === "abc123" && rv.state === "s1");

  var threw = false;
  try { await oauth.parseCallback({ code: "abc", iss: "https://attacker.example" }); }
  catch (e) { threw = /iss-mismatch-callback/.test(e.code) && /RFC 9207/.test(e.message); }
  check("oauth.parseCallback: iss mismatch refused (RFC 9207)",   threw);

  threw = false;
  try { await oauth.parseCallback({ error: "access_denied", error_description: "user said no" }); }
  catch (e) { threw = /op-error/.test(e.code); }
  check("oauth.parseCallback: OP error param refused",            threw);

  threw = false;
  try { await oauth.parseCallback({ code: "abc", state: "wrong" }, { expectedState: "expected" }); }
  catch (e) { threw = /state-mismatch/.test(e.code); }
  check("oauth.parseCallback: state mismatch refused (CSRF)",     threw);

  threw = false;
  try { await oauth.parseCallback({ code: "abc" }, { requireIssParam: true }); }
  catch (e) { threw = /missing-iss-callback/.test(e.code); }
  check("oauth.parseCallback: requireIssParam refuses missing iss", threw);

  threw = false;
  try { await oauth.parseJarmResponse(""); }
  catch (e) { threw = /no-jarm-response/.test(e.code); }
  check("oauth.parseJarmResponse: empty refused",                 threw);

  threw = false;
  try { await oauth.parseJarmResponse("not-a-jws"); }
  catch (e) { threw = /malformed-jarm-response/.test(e.code); }
  check("oauth.parseJarmResponse: non-3-segment refused",         threw);

  threw = false;
  try {
    await oauth.refreshAccessToken("rt-1", { seen: async function () { return true; } });
  } catch (e) { threw = /refresh-token-replay/.test(e.code); }
  check("oauth.refreshAccessToken: seen()=true refuses replay",   threw);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
