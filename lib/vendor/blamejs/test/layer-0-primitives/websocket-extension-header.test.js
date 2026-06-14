"use strict";
/**
 * websocket _parseExtensionHeader — Sec-WebSocket-Extensions parser
 * (RFC 7692 permessage-deflate negotiation feeds off this).
 *
 * Focus: the extension-parameter name is client-controlled, so the
 * params map is built from [name, value] pairs through Object.fromEntries
 * onto a null-prototype object — never a computed-write (`params[name] =
 * value`) sink. Verifies a hostile `__proto__` / `constructor` /
 * `prototype` parameter name does NOT pollute Object.prototype
 * (CWE-915 / CWE-1321) and that the legitimate parameter shape is
 * unchanged.
 *
 * Run standalone: `node test/layer-0-primitives/websocket-extension-header.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var _parseExtensionHeader = b.websocket._parseExtensionHeader;

function testParsesParamsSuccessPath() {
  var out = _parseExtensionHeader(
    "permessage-deflate; client_max_window_bits=12; server_no_context_takeover, foo; bar=baz"
  );
  check("ext: two extensions parsed", Array.isArray(out) && out.length === 2);
  check("ext: first name lower-cased", out[0].name === "permessage-deflate");
  check("ext: param value parsed", out[0].params.client_max_window_bits === "12");
  check("ext: valueless param is boolean true",
        out[0].params.server_no_context_takeover === true);
  check("ext: second extension name", out[1].name === "foo");
  check("ext: second extension param", out[1].params.bar === "baz");
}

function testParamsMapHasNullPrototype() {
  var out = _parseExtensionHeader("permessage-deflate; client_max_window_bits=15");
  check("ext: params map has null prototype",
        Object.getPrototypeOf(out[0].params) === null);
}

function testRejectsPoisonedParamNames() {
  var out = _parseExtensionHeader(
    "permessage-deflate; __proto__=evil; constructor=evil2; prototype=evil3; client_max_window_bits=10"
  );
  var params = out[0].params;
  check("ext: __proto__ param dropped",
        !Object.prototype.hasOwnProperty.call(params, "__proto__"));
  check("ext: constructor param dropped",
        !Object.prototype.hasOwnProperty.call(params, "constructor"));
  check("ext: prototype param dropped",
        !Object.prototype.hasOwnProperty.call(params, "prototype"));
  check("ext: legitimate param still present alongside dropped ones",
        params.client_max_window_bits === "10");
  check("ext: Object.prototype not polluted",
        ({}).evil === undefined && Object.prototype.evil === undefined);
}

function testProtoValueViaFromEntriesDoesNotEscalate() {
  // Even if a future grammar change let `__proto__` reach the pair list,
  // a null-prototype accumulator + Object.fromEntries materialization
  // can only create an OWN `__proto__` property — it can never mutate the
  // prototype chain. The current parser drops the name outright; this is
  // the structural backstop.
  var before = Object.prototype.toString;
  _parseExtensionHeader("permessage-deflate; __proto__=x");
  check("ext: Object.prototype.toString intact after parse",
        Object.prototype.toString === before);
  check("ext: a fresh object still inherits toString",
        typeof ({}).toString === "function");
}

async function run() {
  testParsesParamsSuccessPath();
  testParamsMapHasNullPrototype();
  testRejectsPoisonedParamNames();
  testProtoValueViaFromEntriesDoesNotEscalate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
