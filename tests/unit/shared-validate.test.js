"use strict";

/**
 * validateEmail refuses an address that carries a control character before it
 * trims the value. The check is b.codepointClass.firstControlCharOffset with
 * forbidTab set.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert");
var b = require("../../lib/vendor/blamejs");
var { validateEmail } = require("../../app/shared/validate");

var ch = String.fromCharCode;

describe("validateEmail relies on the b.codepointClass.firstControlCharOffset contract", function () {
  it("firstControlCharOffset with forbidTab reports TAB, CR, LF, NUL, DEL and C1 at their offsets", function () {
    [ch(0x09), ch(0x0d), ch(0x0a), ch(0x00), ch(0x7f), ch(0x85), ch(0x9b)].forEach(function (c) {
      assert.strictEqual(b.codepointClass.firstControlCharOffset("ab" + c + "cd", { forbidTab: true }), 2,
        "U+" + c.charCodeAt(0).toString(16).toUpperCase());
    });
    assert.strictEqual(b.codepointClass.firstControlCharOffset("user@example.com", { forbidTab: true }), -1);
  });

  it("firstControlCharOffset without forbidTab lets TAB through", function () {
    assert.strictEqual(b.codepointClass.firstControlCharOffset("a" + ch(0x09) + "b"), -1);
  });
});

describe("validateEmail", function () {
  it("refuses an address carrying TAB, a line break, NUL, DEL or a C1 control", function () {
    [ch(0x09), ch(0x0a), ch(0x0d), ch(0x00), ch(0x7f), ch(0x85)].forEach(function (c) {
      assert.deepStrictEqual(validateEmail("user" + c + "@example.com"),
        { valid: false, reason: "Invalid email format." }, "U+" + c.charCodeAt(0).toString(16).toUpperCase());
    });
  });

  it("refuses a control character at the edge of the value, before trimming", function () {
    assert.strictEqual(validateEmail(ch(0x00) + "user@example.com").valid, false);
    assert.strictEqual(validateEmail("user@example.com" + ch(0x7f)).valid, false);
  });

  it("trims and lowercases an ordinary address", function () {
    assert.deepStrictEqual(validateEmail("  User@Example.com "), { valid: true, email: "user@example.com" });
  });

  it("refuses an address longer than EMAIL_MAX_LENGTH characters", function () {
    var longest = "d".repeat(242) + "@example.com";
    assert.strictEqual(longest.length, 254);
    assert.deepStrictEqual(validateEmail(longest), { valid: true, email: longest });
    assert.deepStrictEqual(validateEmail("d" + longest), { valid: false, reason: "Email too long." });
  });
});
