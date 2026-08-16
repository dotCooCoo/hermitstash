"use strict";

/**
 * A release gate must not answer from a lookup that never ran.
 *
 * scripts/release.js reads git and gh through capture(), which returns "" when a
 * command ran and printed nothing, and null when it did not run at all. Under a
 * truthiness test those collapse, and the collapsed reading is the unsafe one:
 *
 *   gitClean:      !null === true   → an unreadable `git status` is a clean tree
 *   remoteHasTag:  !!null === false → an unreadable `ls-remote` is "not published"
 *
 * Neither is theoretical here. The public clean-tree check runs immediately
 * after the tree is wiped and re-exported, so "clean" means "nothing to commit"
 * and the tag would land on the previous content; a file-syncing agent holding a
 * handle in that repo is the recorded failure on this machine. And the ls-remote
 * check is the guard that stops an already-published tag being moved, which the
 * ruleset refuses at the GitHub edge anyway — the local guard is what explains
 * why before the push.
 *
 * These tests read the source because the helpers are private to a CLI script
 * with no exports. That makes them anchored assertions: each one first proves
 * the thing it is inspecting still exists, so this fails loudly if the helpers
 * are renamed rather than passing on a slice of nothing.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var path = require("node:path");

var src = fs.readFileSync(path.join(__dirname, "..", "..", "scripts", "release.js"), "utf8");

// Pull one function body out by name, bounded at the next top-level `function`.
function body(name) {
  var start = src.indexOf("function " + name + "(");
  assert.ok(start !== -1, "release.js must still define " + name + " for this test to mean anything");
  var next = src.indexOf("\nfunction ", start + 1);
  return src.slice(start, next === -1 ? src.length : next);
}

describe("release lookups distinguish an empty answer from no answer", function () {
  it("capture() still reports a failed command as null, not as empty output", function () {
    var fn = body("capture");
    assert.match(fn, /catch \(_e\) \{ return null; \}/,
      "the null-on-failure contract is what every caller below is written against");
    assert.match(fn, /\.trim\(\)/, "and a successful run is returned trimmed, so no output is \"\"");
  });

  it("gitClean answers null when git could not be read", function () {
    var fn = body("gitClean");
    assert.match(fn, /=== null \? null :/,
      "gitClean must pass a failed lookup through as null rather than folding it into a boolean");
    assert.ok(!/return !gitCap/.test(fn),
      "`return !gitCap(...)` reads an unreadable tree as clean — the shape this test exists to stop");
  });

  it("remoteHasTag answers null when the remote could not be asked", function () {
    var fn = body("remoteHasTag");
    assert.match(fn, /=== null \? null :/,
      "remoteHasTag must pass a failed lookup through as null");
    assert.ok(!/return !!gitCap/.test(fn),
      "`return !!gitCap(...)` reads an unreachable remote as \"tag not published\"");
  });

  it("every caller of gitClean handles the unreadable case", function () {
    // Truthiness on a tri-state is the regression. Each call site must compare
    // against null before using the value.
    var callSites = src.split("\n").map(function (line, i) {
      return { line: i + 1, text: line };
    }).filter(function (l) {
      return /gitClean\(/.test(l.text) && !/^function gitClean/.test(l.text.trim());
    });
    assert.ok(callSites.length >= 3, "expected the status, commit and sync call sites, found " + callSites.length);

    callSites.forEach(function (site) {
      // The decision may be on the same line or within the few lines after it.
      var window = src.split("\n").slice(site.line - 1, site.line + 8).join("\n");
      assert.match(window, /=== null|!== null/,
        "gitClean call at line " + site.line + " must decide what an unreadable tree means: " + site.text.trim());
    });
  });

  it("the sync stage refuses rather than skipping the commit it cannot judge", function () {
    var start = src.indexOf("var publicClean = gitClean(PUBLIC_REPO);");
    assert.ok(start !== -1, "the sync stage must still read the public tree state");
    var window = src.slice(start, start + 900);
    assert.match(window, /publicClean === null/, "it must test for the unreadable case");
    assert.match(window, /return 1;/, "and stop the stage rather than continuing to tag");
    // The dangerous ordering: the wipe already ran, so silence here ships stale content.
    assert.match(window, /NOT committed/i,
      "and say that the tree is updated but uncommitted, which is what the operator must act on");
  });

  it("the tag stage refuses when it cannot tell whether the tag is published", function () {
    var start = src.indexOf("function tagOneRepo(");
    assert.ok(start !== -1, "tagOneRepo must still exist");
    var window = src.slice(start, start + 2200);

    assert.match(window, /var published = remoteHasTag\(dir, tag\);/,
      "the remote must be asked once and the answer stored");
    var nullBranch = window.indexOf("published === null");
    var boolBranch = window.indexOf("if (published) {");
    assert.ok(nullBranch !== -1, "an unreachable remote must be its own branch");
    assert.ok(boolBranch !== -1, "the published-tag refusal must still exist");
    assert.ok(nullBranch < boolBranch,
      "the null check must come first, or the truthiness branch consumes the unknown case");

    // Asking twice is its own bug: a second lookup that fails after a first
    // that answered reads as falsy and falls through to recreating the tag.
    var chained = window.match(/remoteHasTag\(dir, tag\)/g) || [];
    assert.ok(chained.length <= 2,
      "each decision must reuse one stored answer, not re-ask (found " + chained.length + " calls)");
    assert.ok(!/else if \(remoteHasTag\(/.test(window),
      "branching directly on a fresh remoteHasTag() call re-asks inside the decision");
  });

  it("the post-push check distinguishes 'not there' from 'could not look'", function () {
    var start = src.indexOf("var visible = remoteHasTag(dir, tag);");
    assert.ok(start !== -1, "the post-push visibility check must store its lookup");
    var window = src.slice(start, start + 700);
    assert.match(window, /visible === null/,
      "an unreadable remote after a push is not the same as a tag that did not arrive");
    assert.match(window, /if \(!visible\)/, "and the genuine 'not there' case must still be reported");
  });
});
