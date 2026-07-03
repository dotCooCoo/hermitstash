// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.importmapIntegrity — WICG Import Maps + SRI integrity map.

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testBuildShape() {
  var out = b.importmapIntegrity.build({
    modules: {
      "@app/main": { url: "/static/main.js", body: "console.log('boot');" },
    },
  });
  check("build returns { imports, integrity }",
    out && typeof out.imports === "object" && typeof out.integrity === "object");
  check("build maps specifier → url",
    out.imports["@app/main"] === "/static/main.js");
  check("integrity keyed by url with sha384 default",
    typeof out.integrity["/static/main.js"] === "string" &&
    out.integrity["/static/main.js"].indexOf("sha384-") === 0);
}

function testBuildSha256() {
  var out = b.importmapIntegrity.build({
    modules: { "x": { url: "/x.js", body: Buffer.from("body", "utf8") } },
    hash:    "sha256",
  });
  check("sha256 produces sha256-prefixed integrity",
    out.integrity["/x.js"].indexOf("sha256-") === 0);
}

function testRefusesBadHash() {
  var threw = null;
  try { b.importmapIntegrity.build({ modules: {}, hash: "md5" }); }
  catch (e) { threw = e.code; }
  check("build refuses md5 hash", threw === "importmap/bad-hash");
}

function testImportmapErrorClass() {
  check("ImportmapError exported", typeof b.importmapIntegrity.ImportmapError === "function");
  var e = new b.importmapIntegrity.ImportmapError("importmap/test", "synthetic");
  check("ImportmapError carries code", e.code === "importmap/test");
}

function testScriptTagEscapesScriptBreakout() {
  // A module url containing "</script>" must NOT close the injected
  // <script type="importmap"> element. scriptTag uses the <script>-safe
  // serializer; raw JSON.stringify would leave the "</script>" literal.
  var im = b.importmapIntegrity.build({
    modules: { "x": { url: "/a</script><script>alert(1)</script>", body: "code" } },
  });
  var tag = b.importmapIntegrity.scriptTag(im);
  // Exactly one "</script>" — the tag's own close. The url's "</script>"
  // must be escaped.
  check("scriptTag: only the tag's own </script> is present (url breakout escaped)",
        tag.split("</script>").length - 1 === 1);
  check("scriptTag: the url's < is escaped to \\u003c",
        tag.indexOf("u003c/script") !== -1 && tag.indexOf("/a</script>") === -1);
  // The embedded JSON still parses and yields the original url.
  var jsonText = tag.replace(/^<script[^>]*>/, "").replace(/<\/script>$/, "");
  check("scriptTag: embedded JSON round-trips to the original url",
        JSON.parse(jsonText).imports.x === "/a</script><script>alert(1)</script>");
  // nonce validation: a malformed nonce is refused, not escaped into the tag.
  var threw = null;
  try { b.importmapIntegrity.scriptTag(im, { nonce: '" onload="x' }); } catch (e) { threw = e; }
  check("scriptTag: malformed nonce is refused", threw && threw.code === "importmap/bad-nonce");
}

function run() {
  testBuildShape();
  testBuildSha256();
  testRefusesBadHash();
  testImportmapErrorClass();
  testScriptTagEscapesScriptBreakout();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
