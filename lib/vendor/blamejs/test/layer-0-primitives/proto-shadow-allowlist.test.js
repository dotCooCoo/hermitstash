"use strict";
/**
 * Prototype-shadow / proto-pollution allowlist-bypass class (CWE-1321).
 *
 * An object-literal allowlist (`var MAP = { a: 1 }`) inherits Object.prototype,
 * so MAP["constructor"], MAP["__proto__"], MAP["toString"], MAP["valueOf"],
 * MAP["hasOwnProperty"] are all TRUTHY (and !== undefined) even though never
 * added. A membership gate `if (!MAP[key])` / `if (MAP[key] === undefined)` is
 * therefore BYPASSED by a prototype-named key when `key` is caller- or
 * attacker-controlled, and `var v = MAP[key]` hands back a Function. The fix is
 * `Object.prototype.hasOwnProperty.call(MAP, key)` (own-key only).
 *
 * This drives the SHIPPED public consumer paths with prototype-named inputs and
 * asserts each is refused / resolves to its safe default — never a bypass and
 * never a Function reaching downstream. RED before the v0.15.14 sweep (the
 * bracket lookup is truthy for a proto key → no throw, or a Function returned).
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var PROTO_KEYS = ["constructor", "__proto__", "toString", "valueOf", "hasOwnProperty"];

function _throws(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

function testContentDigestCreateRefusesProtoAlg() {
  // ACTIVE = { "sha-256": ..., "sha-512": ... }. A proto-named algorithm must
  // be refused as unsupported, NOT silently accepted (which previously reached
  // nodeCrypto.createHash(<Function>) and threw an opaque type error).
  PROTO_KEYS.forEach(function (k) {
    var e = _throws(function () { b.contentDigest.create("payload", { algorithms: [k] }); });
    check("contentDigest.create refuses proto-named algorithm '" + k + "'",
      e !== null && /unsupported-algorithm|insecure-algorithm/.test(String(e.code || e.message)));
  });
  // A real algorithm still works (no over-rejection).
  check("contentDigest.create still accepts sha-256",
    typeof b.contentDigest.create("payload", { algorithms: ["sha-256"] }) === "string");
}

function testSqlFnAndPragmaRefuseProtoNames() {
  PROTO_KEYS.forEach(function (k) {
    var e1 = _throws(function () { b.sql.fn(k); });
    check("b.sql.fn refuses proto-named function '" + k + "' (no allowlist bypass)",
      e1 !== null);
    var e2 = _throws(function () { b.sql.pragma(k); });
    check("b.sql.pragma refuses proto-named verb '" + k + "'", e2 !== null);
  });
  // A real allowlisted function/pragma still resolves (no over-rejection).
  check("b.sql.fn still accepts an allowlisted function",
    _throws(function () { b.sql.fn("now"); }) === null);
  check("b.sql.pragma still accepts an allowlisted verb",
    _throws(function () { b.sql.pragma("journal_mode"); }) === null);
}

function testLogCreateRefusesProtoLevel() {
  PROTO_KEYS.forEach(function (k) {
    var e = _throws(function () { b.log.create({ level: k }); });
    check("b.log.create refuses proto-named level '" + k + "'",
      e !== null && /bad-level/.test(String(e.code || e.message)));
  });
  check("b.log.create still accepts level 'info'",
    _throws(function () { var l = b.log.create({ level: "info" }); return l; }) === null);
}

function testCompliancePostureAccessorReturnsNullForProto() {
  // The mail-scanner compliancePosture accessor maps a posture name through its
  // own table; a proto-named posture must resolve to null, not an inherited
  // Function.
  PROTO_KEYS.forEach(function (k) {
    check("mail.scan.compliancePosture('" + k + "') is null (not a Function)",
      b.mail.scan.compliancePosture(k) === null);
  });
  check("mail.scan.compliancePosture('hipaa') still maps to a profile",
    typeof b.mail.scan.compliancePosture("hipaa") === "string");
}

function testMakePostureAccessorPrimitive() {
  var accessor = b.gateContract.makePostureAccessor({ hipaa: "strict", gdpr: "balanced" });
  check("makePostureAccessor maps a known posture", accessor("hipaa") === "strict");
  PROTO_KEYS.forEach(function (k) {
    check("makePostureAccessor('" + k + "') → null (proto key)", accessor(k) === null);
  });
  var withFallback = b.gateContract.makePostureAccessor({ hipaa: "strict" }, { fallback: "default" });
  check("makePostureAccessor honors opts.fallback for unknown", withFallback("nope") === "default");
  check("makePostureAccessor honors opts.fallback for proto key", withFallback("constructor") === "default");
}

function testMailBounceDsnRefusesProtoAction() {
  // DSN_ACTIONS allowlist; a proto-named action must be refused as malformed.
  PROTO_KEYS.forEach(function (k) {
    var e = _throws(function () {
      b.mailBounce.dsn.build({
        finalRecipient: "user@example.com",
        action:         k,
        status:         "5.1.1",
        reportingMta:   "mx.example.com",
      });
    });
    check("mailBounce.dsn.build refuses proto-named action '" + k + "'", e !== null);
  });
}

async function run() {
  testContentDigestCreateRefusesProtoAlg();
  testSqlFnAndPragmaRefuseProtoNames();
  testLogCreateRefusesProtoLevel();
  testCompliancePostureAccessorReturnsNullForProto();
  testMakePostureAccessorPrimitive();
  testMailBounceDsnRefusesProtoAction();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
