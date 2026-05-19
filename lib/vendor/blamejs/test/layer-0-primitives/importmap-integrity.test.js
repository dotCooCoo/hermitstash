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

function run() {
  testBuildShape();
  testBuildSha256();
  testRefusesBadHash();
  testImportmapErrorClass();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
