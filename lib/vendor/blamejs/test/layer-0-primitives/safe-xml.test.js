"use strict";
/**
 * b.parsers.xml.parse — security-focused XML parser.
 *
 * Covers the structural defaults (XXE / DOCTYPE / billion-laughs / depth
 * + element + attribute caps) and the prototype-pollution posture: the
 * result tree and every nested object it contains carry a null prototype,
 * and element / attribute names equal to __proto__ / constructor /
 * prototype are rejected with xml/forbidden-name (CWE-1321 / OWASP
 * prototype-pollution).
 *
 * Run standalone: `node test/layer-0-primitives/safe-xml.test.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var xml = b.parsers.xml;

// ---- Baseline parse + shape ----

function testParsesAttributedElement() {
  var result = xml.parse('<root id="x"><child>text</child></root>');
  check("xml.parse returns the root key",
        result && result.root && result.root["@attrs"] && result.root["@attrs"].id === "x");
  check("xml.parse groups child element",
        result.root.child === "text");
}

function testRejectsDoctype() {
  var threw = null;
  try { xml.parse('<!DOCTYPE x SYSTEM "file:///etc/passwd"><root/>'); }
  catch (e) { threw = e; }
  check("xml.parse rejects DOCTYPE (XXE defense)",
        threw && threw.code === "xml/doctype");
}

function testRejectsCustomEntity() {
  var threw = null;
  try { xml.parse("<root>&xxe;</root>"); }
  catch (e) { threw = e; }
  check("xml.parse rejects custom entity (XXE defense)",
        threw && threw.code === "xml/external-entity");
}

// ---- Prototype-pollution posture (CWE-1321) ----

function testResultTreeHasNullPrototype() {
  // A document that exercises every keyed accumulator: attributes (attrs),
  // grouped child elements (grouped / obj), and the element-name wrapper
  // (out). Each must carry a null prototype so a consumer reading an
  // absent key sees undefined, never an inherited Object member.
  var result = xml.parse(
    '<root attr="v"><a>1</a><a>2</a><b><c>deep</c></b></root>'
  );

  check("result wrapper has null prototype",
        Object.getPrototypeOf(result) === null);
  check("element object has null prototype",
        Object.getPrototypeOf(result.root) === null);
  check("@attrs object has null prototype",
        Object.getPrototypeOf(result.root["@attrs"]) === null);
  check("nested element object has null prototype",
        Object.getPrototypeOf(result.root.b) === null);
  check("repeated child became an array",
        Array.isArray(result.root.a) && result.root.a.length === 2);

  // No inherited Object.prototype members leak through any accumulator —
  // a plain {} would surface a function here.
  check("no inherited toString on result",
        result.toString === undefined);
  check("no inherited hasOwnProperty on element object",
        result.root.hasOwnProperty === undefined);
  check("no inherited constructor on @attrs object",
        result.root["@attrs"].constructor === undefined);
}

function testRejectsProtoAttributeName() {
  var threw = null;
  try { xml.parse('<root __proto__="polluted"/>'); }
  catch (e) { threw = e; }
  check("xml.parse rejects __proto__ attribute name",
        threw && threw.code === "xml/forbidden-name");
  // The global Object.prototype was not mutated either way.
  check("Object.prototype not polluted by __proto__ attribute",
        ({}).polluted === undefined);
}

function testRejectsProtoElementName() {
  var threw = null;
  try { xml.parse("<__proto__><x>y</x></__proto__>"); }
  catch (e) { threw = e; }
  check("xml.parse rejects __proto__ element name",
        threw && threw.code === "xml/forbidden-name");
}

function testRejectsConstructorElementName() {
  var threw = null;
  try { xml.parse("<root><constructor>x</constructor></root>"); }
  catch (e) { threw = e; }
  check("xml.parse rejects constructor child element name",
        threw && threw.code === "xml/forbidden-name");
}

function testRejectsPrototypeElementName() {
  var threw = null;
  try { xml.parse("<prototype/>"); }
  catch (e) { threw = e; }
  check("xml.parse rejects prototype element name",
        threw && threw.code === "xml/forbidden-name");
}

function testConstructorAttributeNoFalseDuplicate() {
  // With a plain-object accumulator, attrs["constructor"] would read the
  // inherited Object constructor (not undefined) and a single occurrence
  // would falsely trip the duplicate-attribute guard. The forbidden-name
  // rejection now fires first; assert the code is forbidden-name, not
  // duplicate-attr, so the diagnostic points at the real cause.
  var threw = null;
  try { xml.parse('<root constructor="once"/>'); }
  catch (e) { threw = e; }
  check("constructor attribute → forbidden-name (not false duplicate-attr)",
        threw && threw.code === "xml/forbidden-name");
}

function run() {
  try {
    testParsesAttributedElement();
    testRejectsDoctype();
    testRejectsCustomEntity();
    testResultTreeHasNullPrototype();
    testRejectsProtoAttributeName();
    testRejectsProtoElementName();
    testRejectsConstructorElementName();
    testRejectsPrototypeElementName();
    testConstructorAttributeNoFalseDuplicate();
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
  console.log("OK — safe-xml tests");
}

module.exports = { run: run };
if (require.main === module) run();
