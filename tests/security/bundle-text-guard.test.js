"use strict";

/**
 * Free text from an anonymous uploader is screened for codepoints, not just length.
 *
 * uploaderName and message reach the server from /drop/init, which needs no
 * account. Both were length-sliced and otherwise stored verbatim, then rendered
 * on the bundle page to every visitor and placed into the admin notification —
 * including its SUBJECT line, which carries them with no escaping at all.
 *
 * HTML escaping is the wrong tool for this: it neutralises markup and does
 * nothing about a right-to-left override that reverses how a name reads, or
 * zero-width and Tag-block characters that do not render at all. The adjacent
 * filename path already strips exactly these — this is the remainder that did not.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert");
var b = require("../../lib/vendor/blamejs");

// The policy set the service applies. Kept here so a change to either side
// without the other shows up as a failure rather than as silence.
var TEXT_OPTS = {
  bidiPolicy: "strip", controlPolicy: "strip", nullBytePolicy: "strip",
  zeroWidthPolicy: "strip", tagsPolicy: "strip", confusablePolicy: "allow",
};

describe("uploader-supplied text is screened for hostile codepoints", function () {
  it("strips a right-to-left override used to disguise how a name reads", function () {
    var out = b.guardText.sanitize("Bob ‮gnp.exe", TEXT_OPTS);
    assert.ok(out.indexOf("‮") === -1, "the RTLO must not survive: " + JSON.stringify(out));
  });

  it("strips zero-width, control and Tag-block characters", function () {
    var out = b.guardText.sanitize("a​bc󠀁d", TEXT_OPTS);
    ["​", "", "\uDB40"].forEach(function (ch) {
      assert.ok(out.indexOf(ch) === -1, JSON.stringify(ch) + " must not survive: " + JSON.stringify(out));
    });
  });

  it("leaves an ordinary non-Latin name alone", function () {
    // The screen is worthless if it mangles legitimate names. Homoglyphs are
    // deliberately allowed for the same reason filenames allow them.
    ["日本語の名前", "Müller", "Ольга", "أحمد"].forEach(function (name) {
      assert.equal(b.guardText.sanitize(name, TEXT_OPTS), name,
        name + " is an ordinary name and must pass through unchanged");
    });
  });

  it("the policies are named explicitly, because a profile alone is a no-op", function () {
    // sanitize() with no policies does nothing at all. Passing a profile and
    // assuming it strips is a silent way to ship no protection, so this pins
    // that the explicit set is what does the work.
    var hostile = "x‮y";
    assert.equal(b.guardText.sanitize(hostile), hostile,
      "precondition: sanitize with no policies is a no-op — if this changes, the "
      + "comment in bundle.service.js about explicit policies needs revisiting");
    assert.notEqual(b.guardText.sanitize(hostile, TEXT_OPTS), hostile,
      "the explicit policy set must actually strip");
  });

  it("the service applies it to both anonymous fields", function () {
    var src = require("node:fs").readFileSync(
      require("node:path").join(__dirname, "..", "..", "app", "domain", "uploads", "bundle.service.js"), "utf8");
    assert.match(src, /uploaderName:\s*_safeText\(/, "uploaderName must be screened");
    assert.match(src, /_safeText\(String\(opts\.message\)/, "message must be screened");
  });
});
