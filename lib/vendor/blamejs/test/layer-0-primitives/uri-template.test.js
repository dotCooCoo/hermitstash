// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.uriTemplate (RFC 6570).
 * Oracle: the official uri-templates/uritemplate-test suite (spec-examples,
 * extended-tests, negative-tests) — all 135 cases pass during development.
 * This file embeds a representative slice across all four levels plus the
 * surface, compile-reuse, and malformed-template paths.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

var VARS = {
  count: ["one", "two", "three"], dom: ["example", "com"],
  dub: "me/too", hello: "Hello World!", half: "50%", "var": "value",
  who: "fred", base: "http://example.com/home/", path: "/foo/bar",
  list: ["red", "green", "blue"], keys: { semi: ";", dot: ".", comma: "," },
  v: "6", x: "1024", y: "768", empty: "", undef: undefined,
};

function testSurface() {
  check("b.uriTemplate.expand is a function", typeof b.uriTemplate.expand === "function");
  check("b.uriTemplate.compile is a function", typeof b.uriTemplate.compile === "function");
  check("b.uriTemplate.UriTemplateError is a class", typeof b.uriTemplate.UriTemplateError === "function");
}

function eq(tmpl, want) { check(tmpl + " → " + want, b.uriTemplate.expand(tmpl, VARS) === want); }

function testLevels() {
  // Level 1 — simple string expansion.
  eq("{var}", "value");
  eq("{hello}", "Hello%20World%21");
  // Level 2 — reserved + fragment.
  eq("{+var}", "value");
  eq("{+path}/here", "/foo/bar/here");
  eq("{#path}", "#/foo/bar");
  eq("{+half}", "50%25");
  // Level 3 — multiple vars + path/label/params/query operators.
  eq("{x,y}", "1024,768");
  eq("{+x,hello,y}", "1024,Hello%20World!,768");
  eq("{/var}", "/value");
  eq("{.who}", ".fred");
  eq("{;x,y}", ";x=1024;y=768");
  eq("{?x,y}", "?x=1024&y=768");
  eq("{&x}", "&x=1024");
  // empty value under named operators.
  eq("{;empty}", ";empty");
  eq("{?empty}", "?empty=");
}

function testLevel4() {
  // Prefix modifier.
  eq("{var:3}", "val");
  eq("{var:30}", "value");
  // Explode — list.
  eq("{list}", "red,green,blue");
  eq("{list*}", "red,green,blue");
  eq("{/list*}", "/red/green/blue");
  eq("{?list*}", "?list=red&list=green&list=blue");
  // Explode — associative array.
  eq("{keys}", "semi,%3B,dot,.,comma,%2C");
  eq("{;keys*}", ";semi=%3B;dot=.;comma=%2C");
  eq("{?keys*}", "?semi=%3B&dot=.&comma=%2C");
  // Undefined variables are omitted.
  eq("{undef}", "");
  eq("x{?undef}", "x");
  // Undefined / null members of a list or map are ignored (RFC 6570 §3.2.1).
  check("undefined list member skipped", b.uriTemplate.expand("{?l*}", { l: ["a", undefined, "b", null, "c"] }) === "?l=a&l=b&l=c");
  check("undefined list member skipped (joined)", b.uriTemplate.expand("{l}", { l: ["a", undefined, "b"] }) === "a,b");
  check("all-undefined list omitted", b.uriTemplate.expand("x{?l*}", { l: [undefined, null] }) === "x");
  check("undefined map value skipped", b.uriTemplate.expand("{?m*}", { m: { a: 1, b: undefined, c: 3 } }) === "?a=1&c=3");
  check("undefined map value skipped (joined)", b.uriTemplate.expand("{m}", { m: { a: "1", b: undefined, c: "3" } }) === "a,1,c,3");
}

function testCompileReuse() {
  var t = b.uriTemplate.compile("/users/{id}{?fields*}");
  check("compiled expand A", t.expand({ id: 7, fields: ["name", "email"] }) === "/users/7?fields=name&fields=email");
  check("compiled expand B (reused)", t.expand({ id: 9 }) === "/users/9");
}

function testMalformed() {
  check("unclosed expression throws", code(function () { b.uriTemplate.expand("{var", {}); }) === "uri-template/unclosed");
  check("reserved operator throws", code(function () { b.uriTemplate.expand("{=var}", {}); }) === "uri-template/reserved-operator");
  check("non-numeric prefix throws", code(function () { b.uriTemplate.expand("{var:x}", {}); }) === "uri-template/bad-prefix");
  check("prefix on list throws", code(function () { b.uriTemplate.expand("{list:3}", VARS); }) === "uri-template/prefix-on-list");
  check("unmatched brace throws", code(function () { b.uriTemplate.expand("/id*}", {}); }) === "uri-template/unmatched-brace");
}

async function run() {
  testSurface();
  testLevels();
  testLevel4();
  testCompileReuse();
  testMalformed();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[uri-template] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
