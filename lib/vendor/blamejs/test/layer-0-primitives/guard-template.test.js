// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-template — SSTI content-safety primitive (b.guardTemplate).
 *
 * Covers the pass-through-or-throw sanitize contract: benign text returns
 * unchanged, while a string carrying template-engine syntax throws
 * GuardTemplateError with the offending rule id. Jinja `{{...}}` / ERB
 * `<%...%>` / Pug interpolation shapes are refused at EVERY profile —
 * the SSTI class is never an operator opt-in.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _code(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }

function testGuardTemplateSurface() {
  check("guardTemplate is an object",           typeof b.guardTemplate === "object");
  check("guardTemplate.NAME === 'template'",    b.guardTemplate.NAME === "template");
  check("guardTemplate.sanitize is a function", typeof b.guardTemplate.sanitize === "function");
  check("guardTemplate registered in guardAll",
    b.guardAll.allGuards().some(function (g) { return (g.name || g.NAME) === "template"; }));
  check("frameworkError.GuardTemplateError exposed",
    typeof b.frameworkError.GuardTemplateError === "function");
}

function testSanitizeCleanPassthrough() {
  // Plain prose with no engine syntax survives sanitize verbatim.
  var out = b.guardTemplate.sanitize("Hello world", { profile: "strict" });
  check("benign text passes through unchanged", out === "Hello world");
}

function testSanitizeRefusesJinjaExpression() {
  // `{{7*7}}` is the canonical SSTI probe (Jinja / Twig / Handlebars).
  check("jinja expression refused under strict",
    _code(function () { b.guardTemplate.sanitize("Hello {{7*7}}", { profile: "strict" }); })
      === "template.jinja-expression");
}

function testSanitizeRefusesErbEveryProfile() {
  // ERB `<%= ... %>` interpolation is refused even at permissive.
  check("ERB expression refused at permissive",
    _code(function () { b.guardTemplate.sanitize("x <%= 7 %>", { profile: "permissive" }); })
      === "template.erb-expression");
}

function testSanitizeThrowsGuardTemplateError() {
  var caught = null;
  try { b.guardTemplate.sanitize("#{name}", { profile: "strict" }); }
  catch (e) { caught = e; }
  check("sanitize throws a GuardTemplateError instance",
    caught instanceof b.frameworkError.GuardTemplateError);
}

function run() {
  testGuardTemplateSurface();
  testSanitizeCleanPassthrough();
  testSanitizeRefusesJinjaExpression();
  testSanitizeRefusesErbEveryProfile();
  testSanitizeThrowsGuardTemplateError();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-template] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
