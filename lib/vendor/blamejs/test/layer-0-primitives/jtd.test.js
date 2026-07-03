// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.jtd (RFC 8927 JSON Type Definition).
 * Oracle: a curated subset of the official jsontypedef/json-typedef-spec
 * tests — validation cases (schema + instance -> expected errors) and
 * invalid-schema cases (must throw jtd/bad-schema). The full suites
 * (316 validation + 49 invalid-schema) were run green during development.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn){try{fn();return "NO-THROW";}catch(e){return e.code;}}
function norm(es){return JSON.stringify(es.map(function(e){return JSON.stringify({i:e.instancePath,s:e.schemaPath});}).sort());}

var VALID = [{"schema":{},"instance":null,"errors":[]},{"schema":{"definitions":{"foo":{"type":"boolean"}},"ref":"foo"},"instance":true,"errors":[]},{"schema":{"type":"boolean"},"instance":[],"errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"float32"},"instance":3.14,"errors":[]},{"schema":{"type":"float64"},"instance":true,"errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"float64","nullable":true},"instance":{},"errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"int8","nullable":true},"instance":"foo","errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"uint8"},"instance":[],"errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"uint8"},"instance":256,"errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"int16","nullable":true},"instance":"foo","errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"uint16"},"instance":[],"errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"uint16"},"instance":65536,"errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"int32","nullable":true},"instance":"foo","errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"uint32"},"instance":[],"errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"uint32"},"instance":4294967296,"errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"type":"string","nullable":true},"instance":"foo","errors":[]},{"schema":{"type":"timestamp","nullable":true},"instance":1,"errors":[{"instancePath":[],"schemaPath":["type"]}]},{"schema":{"enum":["foo","bar","baz"]},"instance":1,"errors":[{"instancePath":[],"schemaPath":["enum"]}]},{"schema":{"enum":["foo","bar","baz"],"nullable":true},"instance":"quux","errors":[{"instancePath":[],"schemaPath":["enum"]}]},{"schema":{"elements":{"type":"string"},"nullable":true},"instance":"foo","errors":[{"instancePath":[],"schemaPath":["elements"]}]},{"schema":{"properties":{"foo":{"type":"string"}}},"instance":"foo","errors":[{"instancePath":[],"schemaPath":["properties"]}]},{"schema":{"properties":{"foo":{"type":"string"}},"optionalProperties":{"bar":{"type":"string"}}},"instance":"foo","errors":[{"instancePath":[],"schemaPath":["properties"]}]},{"schema":{"properties":{"foo":{"type":"string"}},"additionalProperties":false},"instance":{"foo":"foo","bar":"bar"},"errors":[{"instancePath":["bar"],"schemaPath":[]}]},{"schema":{"optionalProperties":{"foo":{"type":"string"}},"additionalProperties":true},"instance":{},"errors":[]},{"schema":{"values":{"type":"string"},"nullable":true},"instance":true,"errors":[{"instancePath":[],"schemaPath":["values"]}]},{"schema":{"discriminator":"foo","mapping":{}},"instance":true,"errors":[{"instancePath":[],"schemaPath":["discriminator"]}]}];
var INVALID = [null,3.14,{"foo":123},{"definitions":{"foo":123}},{"ref":"foo"},{"type":123},{"enum":[]},{"elements":123},{"properties":{"foo":{"definitions":{"x":{}}}}},{"properties":{},"additionalProperties":123},{"values":{"definitions":{"x":{}}}},{"discriminator":"foo","mapping":{"x":{"properties":{},"definitions":{"x":{}}}}},{"discriminator":"foo","mapping":{"x":{"properties":{"foo":{}}}}},{"type":"uint32","enum":["foo"]}];

function testSurface(){
  check("b.jtd.validate is a function", typeof b.jtd.validate === "function");
  check("b.jtd.isValid is a function", typeof b.jtd.isValid === "function");
  check("b.jtd.isValid true for conforming", b.jtd.isValid({type:"string"}, "x") === true);
  check("b.jtd.isValid false for non-conforming", b.jtd.isValid({type:"string"}, 1) === false);
  check("b.jtd.JtdError thrown on bad schema", code(function(){ b.jtd.validate({foo:1}, null); }) === "jtd/bad-schema" && typeof b.jtd.JtdError === "function");
}
function testValidation(){
  var pass=0;
  VALID.forEach(function(t,i){ var got; try{got=b.jtd.validate(t.schema,t.instance);}catch(e){check("jtd validate #"+i+": "+e.message,false);return;} if(norm(got)===norm(t.errors))pass++; else check("jtd result #"+i+" got "+JSON.stringify(got).slice(0,70),false); });
  check("JTD validation: all "+VALID.length+" cases match", pass===VALID.length);
}
function testInvalidSchemas(){
  var rej=0;
  INVALID.forEach(function(s,i){ if(code(function(){ b.jtd.validate(s, null); })==="jtd/bad-schema") rej++; else check("jtd invalid-schema #"+i+" rejected: "+JSON.stringify(s).slice(0,60),false); });
  check("JTD well-formedness: all "+INVALID.length+" malformed schemas rejected", rej===INVALID.length);
}
function testExplicit(){
  check("uint32 rejects negative", JSON.stringify(b.jtd.validate({properties:{id:{type:"uint32"}}},{id:-1})) === JSON.stringify([{instancePath:["id"],schemaPath:["properties","id","type"]}]));
  check("timestamp accepts RFC3339", b.jtd.isValid({type:"timestamp"}, "1985-04-12T23:20:50.52Z"));
  check("timestamp rejects bad date", !b.jtd.isValid({type:"timestamp"}, "1985-13-12T23:20:50Z"));
  check("additionalProperties false rejects extra", !b.jtd.isValid({properties:{a:{type:"string"}}},{a:"x",b:"y"}));
  check("nullable allows null", b.jtd.isValid({type:"string",nullable:true}, null));
  // RFC 3339 timezone offset range is enforced.
  check("timestamp rejects offset hour > 23", !b.jtd.isValid({type:"timestamp"}, "2020-01-01T00:00:00+24:00"));
  check("timestamp rejects offset minute > 59", !b.jtd.isValid({type:"timestamp"}, "2020-01-01T00:00:00+00:99"));
  check("timestamp accepts valid offset", b.jtd.isValid({type:"timestamp"}, "2020-01-01T00:00:00+05:30"));
  // metadata must be an object.
  check("non-object metadata rejected", code(function(){ b.jtd.validate({type:"string",metadata:1}, "x"); }) === "jtd/bad-schema");
  check("object metadata accepted", b.jtd.isValid({type:"string",metadata:{doc:"x"}}, "y"));
}
async function run(){ testSurface(); testValidation(); testInvalidSchemas(); testExplicit(); }
module.exports={run:run};
if(require.main===module){ run().then(function(){console.log("[jtd] OK — "+helpers.getChecks()+" checks passed");},function(e){console.error("FAIL:",e&&e.stack||e);process.exit(1);}); }
