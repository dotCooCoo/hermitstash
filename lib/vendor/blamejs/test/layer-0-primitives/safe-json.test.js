// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeJson parse caps — the six documented limit constants and the fact
 * that b.safeJson.parse actually enforces them.
 *
 * These are not typeof assertions: each test drives the real parse consumer
 * path so the constant's advertised value is proven to be the boundary the
 * primitive honors. The DEFAULT_* trio is exercised end-to-end (a payload one
 * step past the cap refuses with the documented .code; a payload at/under it
 * parses). The ABSOLUTE_* trio is the ceiling opts.max* clamps down to — the
 * depth ceiling is exercised via a real clamp (a huge maxDepth request is
 * pinned back to 1000), and the byte / key ceilings are exercised as the higher
 * working cap that changes a parse outcome the default refuses. Fixtures are
 * sized from the constants themselves so a value drift breaks the test.
 */

var { check, b } = require("../helpers");

function _nest(n) {
  return "[".repeat(n) + "1" + "]".repeat(n);
}

function _objectWithKeys(n) {
  var pairs = [];
  for (var i = 0; i < n; i += 1) pairs.push('"k' + i + '":0');
  return "{" + pairs.join(",") + "}";
}

function _code(fn) {
  try { fn(); return "OK"; }
  catch (e) { return e && e.code; }
}

// ---- DEFAULT_MAX_BYTES ----

function testDefaultMaxBytes() {
  check("b.safeJson.DEFAULT_MAX_BYTES is the advertised 1 MiB",
        b.safeJson.DEFAULT_MAX_BYTES === 1048576);

  // A JSON string body just past the default cap refuses BEFORE the parser
  // sees it — the whole point of the byte cap is DoS-avoidance on the parse
  // thread. Sizing the payload off the constant means a value drift flips it.
  var overDefault = '"' + "x".repeat(b.safeJson.DEFAULT_MAX_BYTES + 100) + '"';
  check("parse refuses a body larger than DEFAULT_MAX_BYTES with json/too-large",
        _code(function () { b.safeJson.parse(overDefault); }) === "json/too-large");

  // A small body sails through under the same default cap.
  var underDefault = '"' + "x".repeat(64) + '"';
  check("parse accepts a body well under DEFAULT_MAX_BYTES",
        b.safeJson.parse(underDefault) === "x".repeat(64));

  // Proof the DEFAULT is what applied above: raising maxBytes past the body
  // size accepts the same over-default payload the default rejected.
  check("raising opts.maxBytes above the body accepts what the default refused",
        typeof b.safeJson.parse(overDefault, {
          maxBytes: b.safeJson.DEFAULT_MAX_BYTES + 200,
        }) === "string");
}

// ---- DEFAULT_MAX_DEPTH ----

function testDefaultMaxDepth() {
  check("b.safeJson.DEFAULT_MAX_DEPTH is the advertised 100",
        b.safeJson.DEFAULT_MAX_DEPTH === 100);

  // Nesting one level past the default bound refuses; nesting exactly at the
  // bound parses. Bounds stack-overflow risk for downstream clone/merge walks.
  var tooDeep = _nest(b.safeJson.DEFAULT_MAX_DEPTH + 1);
  check("parse refuses nesting past DEFAULT_MAX_DEPTH with json/too-deep",
        _code(function () { b.safeJson.parse(tooDeep); }) === "json/too-deep");

  var atDepth = _nest(b.safeJson.DEFAULT_MAX_DEPTH);
  check("parse accepts nesting at DEFAULT_MAX_DEPTH",
        Array.isArray(b.safeJson.parse(atDepth)));
}

// ---- DEFAULT_MAX_KEYS ----

function testDefaultMaxKeys() {
  check("b.safeJson.DEFAULT_MAX_KEYS is the advertised 10 000",
        b.safeJson.DEFAULT_MAX_KEYS === 10000);

  // One key past the default per-object cap refuses (CVE-2026-21717 HashDoS
  // guard); exactly at the cap parses.
  var tooMany = _objectWithKeys(b.safeJson.DEFAULT_MAX_KEYS + 1);
  check("parse refuses an object past DEFAULT_MAX_KEYS with json/too-many-keys",
        _code(function () { b.safeJson.parse(tooMany); }) === "json/too-many-keys");

  var atKeys = _objectWithKeys(b.safeJson.DEFAULT_MAX_KEYS);
  check("parse accepts an object at DEFAULT_MAX_KEYS",
        Object.keys(b.safeJson.parse(atKeys)).length === b.safeJson.DEFAULT_MAX_KEYS);
}

// ---- ABSOLUTE_MAX_BYTES ----

function testAbsoluteMaxBytes() {
  check("b.safeJson.ABSOLUTE_MAX_BYTES is the advertised 64 MiB",
        b.safeJson.ABSOLUTE_MAX_BYTES === 67108864);
  check("ABSOLUTE_MAX_BYTES sits above the default (real headroom ceiling)",
        b.safeJson.ABSOLUTE_MAX_BYTES > b.safeJson.DEFAULT_MAX_BYTES);

  // Exercised as the higher working cap: a body the default refuses is
  // accepted when maxBytes is raised to the absolute ceiling. The full clamp
  // at 64 MiB is asserted by value only — allocating a 64 MiB body per process
  // is unsuitable for the parallel smoke harness.
  var overDefault = '"' + "x".repeat(b.safeJson.DEFAULT_MAX_BYTES + 100) + '"';
  check("default cap refuses the over-default body",
        _code(function () { b.safeJson.parse(overDefault); }) === "json/too-large");
  check("maxBytes = ABSOLUTE_MAX_BYTES accepts the over-default body",
        typeof b.safeJson.parse(overDefault, {
          maxBytes: b.safeJson.ABSOLUTE_MAX_BYTES,
        }) === "string");
}

// ---- ABSOLUTE_MAX_DEPTH ----

function testAbsoluteMaxDepth() {
  check("b.safeJson.ABSOLUTE_MAX_DEPTH is the advertised 1000",
        b.safeJson.ABSOLUTE_MAX_DEPTH === 1000);
  check("ABSOLUTE_MAX_DEPTH sits above the default",
        b.safeJson.ABSOLUTE_MAX_DEPTH > b.safeJson.DEFAULT_MAX_DEPTH);

  // A caller asking for a maxDepth far above the ceiling is silently clamped
  // to ABSOLUTE_MAX_DEPTH — so nesting one past the ceiling still refuses even
  // with the inflated request, and nesting at the ceiling still parses.
  var hugeRequest = b.safeJson.ABSOLUTE_MAX_DEPTH * 100;
  var pastCeiling = _nest(b.safeJson.ABSOLUTE_MAX_DEPTH + 1);
  check("an inflated maxDepth is clamped to ABSOLUTE_MAX_DEPTH (refuses past it)",
        _code(function () {
          b.safeJson.parse(pastCeiling, { maxDepth: hugeRequest });
        }) === "json/too-deep");

  var atCeiling = _nest(b.safeJson.ABSOLUTE_MAX_DEPTH);
  check("nesting at ABSOLUTE_MAX_DEPTH parses under the clamped cap",
        Array.isArray(b.safeJson.parse(atCeiling, { maxDepth: hugeRequest })));
}

// ---- ABSOLUTE_MAX_KEYS ----

function testAbsoluteMaxKeys() {
  check("b.safeJson.ABSOLUTE_MAX_KEYS is the advertised 1 000 000",
        b.safeJson.ABSOLUTE_MAX_KEYS === 1000000);
  check("ABSOLUTE_MAX_KEYS sits above the default (real headroom ceiling)",
        b.safeJson.ABSOLUTE_MAX_KEYS > b.safeJson.DEFAULT_MAX_KEYS);

  // Exercised as the higher working cap: an object the default refuses is
  // accepted when maxKeys is raised to the absolute ceiling. The full clamp at
  // 1 000 000 keys is asserted by value only — allocating a million-key object
  // per process is unsuitable for the parallel smoke harness.
  var overDefault = _objectWithKeys(b.safeJson.DEFAULT_MAX_KEYS + 1);
  check("default cap refuses the over-default object",
        _code(function () { b.safeJson.parse(overDefault); }) === "json/too-many-keys");
  check("maxKeys = ABSOLUTE_MAX_KEYS accepts the over-default object",
        Object.keys(b.safeJson.parse(overDefault, {
          maxKeys: b.safeJson.ABSOLUTE_MAX_KEYS,
        })).length === b.safeJson.DEFAULT_MAX_KEYS + 1);
}

async function run() {
  testDefaultMaxBytes();
  testDefaultMaxDepth();
  testDefaultMaxKeys();
  testAbsoluteMaxBytes();
  testAbsoluteMaxDepth();
  testAbsoluteMaxKeys();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
