// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.canonicalJson.stringifyJcs — RFC 8785 (JSON Canonicalization
 * Scheme) strict mode. Refuses input types JCS does not cover.
 */

var helpers = require("../helpers");
var check  = helpers.check;
var canonicalJson = require("../../lib/canonical-json");

async function run() {
  var s = canonicalJson.stringifyJcs({ b: 1, a: 2 });
  check("canonical-json stringifyJcs: keys sorted",
    s === '{"a":2,"b":1}');

  var threw;
  try { canonicalJson.stringifyJcs({ x: BigInt(1) }); } catch (e) { threw = e; }
  check("canonical-json stringifyJcs: BigInt refused",
    threw && /BigInt/.test(threw.message));

  var threw2;
  try { canonicalJson.stringifyJcs({ x: Buffer.from([1, 2, 3]) }); } catch (e) { threw2 = e; }
  check("canonical-json stringifyJcs: Buffer refused",
    threw2 && /Buffer/.test(threw2.message));

  var threw3;
  try { canonicalJson.stringifyJcs({ x: new Date() }); } catch (e) { threw3 = e; }
  check("canonical-json stringifyJcs: Date refused",
    threw3 && /Date/.test(threw3.message));

  var sLegacy = canonicalJson.stringify({ x: BigInt(1) });
  check("canonical-json stringify (non-JCS): BigInt → string accepted",
    sLegacy === '{"x":"1"}');
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[canonical-json-jcs] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
