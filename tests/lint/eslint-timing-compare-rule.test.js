"use strict";

/**
 * The no-early-exit-timing-compare rule, exercised in both directions.
 *
 * The rule guards a real defect this codebase shipped: two-factor backup-code
 * redemption and passkey lookup each compared a presented value against a list
 * and stopped at the first match, so the response time reported the match's
 * position. Every comparison was individually constant time; the leak was the
 * iteration count.
 *
 * A first attempt scanned source text and had to decide, with regexes, what
 * negates a call, where an if-branch ends, whether a `return` belongs to the
 * loop or a callback inside it, and whether a `break` leaves this loop or a
 * nested one. It got each of those wrong in turn. Every REJECT case below is one
 * of those — a shape that is correct and must not be reported — and they are the
 * reason the rule is an AST rule rather than a pattern.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert");
var path = require("node:path");

var { Linter } = require(path.join(__dirname, "..", "node_modules", "eslint", "lib", "linter"));
var config = require(path.join(__dirname, "..", "..", "eslint.config.js"));

// Pull the rule out of the canonical config so this tests the SHIPPED rule
// rather than a copy that can drift from it.
var ruleBlock = config.filter(function (c) { return c.plugins && c.plugins.hermitstash; })[0];
var rule = ruleBlock && ruleBlock.plugins.hermitstash.rules["no-early-exit-timing-compare"];

function lint(code) {
  var linter = new Linter({ configType: "flat" });
  return linter.verify(code, [{
    files: ["**/*.js"],
    plugins: { hermitstash: { rules: { "no-early-exit-timing-compare": rule } } },
    languageOptions: { ecmaVersion: 2022, sourceType: "commonjs" },
    rules: { "hermitstash/no-early-exit-timing-compare": "error" },
  }], "candidate.js");
}

var FLAG = [
  ["for + break", "for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p, l[i])) { idx = i; break; } }"],
  ["for + return", "function f(){ for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p, l[i])) { return i; } } }"],
  ["while + return", "function f(){ while (i<n) { if (b.crypto.timingSafeEqual(p, l[i])) { return true; } i++; } }"],
  ["for..of + break", "for (var c of cands) { if (b.crypto.timingSafeEqual(p, c)) { break; } }"],
  ["brace-less branch", "function f(){ for (var i=0;i<n;i++) if (b.crypto.timingSafeEqual(p,l[i])) return i; }"],
  ["throw on match", "function f(){ for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) throw new Error('dup'); } }"],
  ["labelled break", "outer: for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) { break outer; } }"],
  ["bare identifier callee", "function f(){ for (var i=0;i<n;i++) { if (timingSafeEqual(p,l[i])) return i; } }"],
  ["stored result then break", "for (var i=0;i<n;i++) { var m = b.crypto.timingSafeEqual(p,l[i]); if (m) break; }"],
  ["stored result then return", "function f(){ for (var i=0;i<n;i++) { var hit = b.crypto.timingSafeEqual(p,l[i]); if (hit) { return i; } } }"],
  ["real exit beside a nested callback", "function f(){ for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) { xs.map(function(x){ return x+1; }); return i; } } }"],
  // An even number of negations is a POSITIVE match. Bailing at the first `!`
  // read this as a mismatch guard and let it through.
  ["double negation", "function f(){ for (var i=0;i<n;i++) { if (!!b.crypto.timingSafeEqual(p,l[i])) return i; } }"],
  ["negated === false", "function f(){ for (var i=0;i<n;i++) { if (!(b.crypto.timingSafeEqual(p,l[i]) === false)) return i; } }"],
  // A label on something OUTSIDE the branch does carry control past the loop.
  ["break to an outer label", "outer: for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) { inner: { break outer; } } }"],
  // Assignment to an EXISTING binding, not a declaration. The identifier here is
  // a reference, so resolving by definition node never matched it.
  ["assignment to an outer binding", "function f(){ var hit; for (var i=0;i<n;i++) { hit = b.crypto.timingSafeEqual(p,l[i]); if (hit) break; } return hit; }"],
  ["assignment then return", "function f(){ var hit; for (var i=0;i<n;i++) { hit = b.crypto.timingSafeEqual(p,l[i]); if (hit) { return i; } } }"],
  // The stored result tested in a shape other than a bare identifier. Same leak.
  ["stored result === true", "for (var i=0;i<n;i++) { var hit = b.crypto.timingSafeEqual(p,l[i]); if (hit === true) break; }"],
  ["stored result double-negated", "function f(){ for (var i=0;i<n;i++) { var hit = b.crypto.timingSafeEqual(p,l[i]); if (!!hit) return i; } }"],
  ["stored result in a conjunction", "for (var i=0;i<n;i++) { var hit = b.crypto.timingSafeEqual(p,l[i]); if (hit && enabled) break; }"],
  // A MATCH selects the alternate here, and the alternate exits. Checking only
  // the consequent reads this as safe.
  ["negated condition, else exits", "function f(){ for (var i=0;i<n;i++) { if (!b.crypto.timingSafeEqual(p,l[i])) continue; else return l[i]; } }"],
  // `continue outer` from the inner loop abandons the inner scan's remaining
  // candidates — the same early exit a labelled break performs.
  ["labelled continue out of a nested loop", "outer: for (var g=0;g<m;g++) { for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) continue outer; } }"],
  // The comparison stored through a wrapper is still stored.
  ["stored via === true", "for (var i=0;i<n;i++) { var hit = b.crypto.timingSafeEqual(p,l[i]) === true; if (hit) break; }"],
  ["stored via conjunction", "function f(){ var hit; for (var i=0;i<n;i++) { hit = b.crypto.timingSafeEqual(p,l[i]) && enabled; if (hit) return i; } }"],
];

var REJECT = [
  // What this repo now does: every candidate compared, first match kept.
  ["compares all, keeps first", "for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i]) && idx === -1) idx = i; }"],
  // Fail-fast on a MISMATCH reveals nothing about position.
  ["negated guard + continue", "for (var i=0;i<n;i++) { if (!b.crypto.timingSafeEqual(p,l[i])) continue; tally(i); }"],
  ["=== false fail-fast", "function f(){ for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i]) === false) return null; } }"],
  ["!== true fail-fast", "function f(){ for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i]) !== true) return null; } }"],
  // The exit belongs to a later, unrelated branch.
  ["unrelated later exit", "function f(){ for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) { matched = true; } if (done) return matched; } }"],
  // A return inside a callback leaves the callback, not the loop.
  ["return inside a callback", "for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) { xs.map(function(x){ return x+1; }); } }"],
  ["return inside an arrow", "for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) { xs.map(function(x) { return x; }); } }"],
  // A break inside a NESTED loop or switch stops that construct only.
  ["break in a nested loop", "for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) { for (var j=0;j<m;j++) { break; } } }"],
  ["break in a nested switch", "for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) { switch (k) { case 1: break; } } }"],
  // Not in a loop at all — a single-pair verifier.
  ["single pair, no loop", "function f(){ if (b.crypto.timingSafeEqual(actual, expected)) return true; return false; }"],
  ["verifier after a loop", "function f(){ for (var c of list) { tally(c); } if (b.crypto.timingSafeEqual(a,e)) return true; }"],
  // Stored, but used negatively.
  ["stored result, negated", "for (var i=0;i<n;i++) { var ok = b.crypto.timingSafeEqual(p,l[i]); if (!ok) continue; tally(i); }"],
  // A labelled break whose label is declared INSIDE the branch stops that
  // construct; the candidate scan carries on.
  ["break to a label inside the branch", "for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) { inner: { break inner; } } }"],
  // Triple negation is a mismatch guard again.
  ["triple negation", "for (var i=0;i<n;i++) { if (!!!b.crypto.timingSafeEqual(p,l[i])) continue; }"],
  // A labelled block INSIDE the loop but outside the branch: `break block`
  // leaves the block, the iteration continues.
  ["break to a label beside the branch", "for (var i=0;i<n;i++) { block: { if (b.crypto.timingSafeEqual(p,l[i])) break block; } work(); }"],
  // An inner binding that shadows the stored result has nothing to do with the
  // comparison; matching on the NAME reports this as a leak.
  ["shadowed inner binding", "for (var i=0;i<n;i++) { var hit = b.crypto.timingSafeEqual(p,l[i]); { let hit = true; if (hit) break; } }"],
  // Every candidate compared, the answer used ONCE after the loop. This is the
  // correct shape, and reporting it would block the release gate on secure code.
  ["decision taken after the loop", "function f(){ var hit = false; for (var i=0;i<n;i++) { hit = b.crypto.timingSafeEqual(p,l[i]) || hit; } if (hit) return true; return false; }"],
  ["stored result read only after the loop", "function f(){ var hit; for (var i=0;i<n;i++) { hit = b.crypto.timingSafeEqual(p,l[i]); } if (hit) return true; }"],
  // A bare continue moves to the next candidate; the scan runs to the end.
  ["bare continue on a match", "for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) continue; tally(i); }"],
  // And a labelled continue aimed at the candidate loop's OWN label does the
  // same thing the bare form does.
  ["continue to the loop's own label", "outer: for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) continue outer; tally(i); }"],
  // The initialiser INVERTS the result, so a truthy binding is a mismatch and
  // exiting on it reveals nothing about position.
  ["negated store, fail-fast on mismatch", "function f(){ for (var i=0;i<n;i++) { var mismatch = !b.crypto.timingSafeEqual(p,l[i]); if (mismatch) return false; } return true; }"],
  ["=== false store, fail-fast", "function f(){ for (var i=0;i<n;i++) { var bad = b.crypto.timingSafeEqual(p,l[i]) === false; if (bad) return false; } }"],
  // The branch IS a loop, and owns its own break.
  ["branch is a loop owning its break", "for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i])) while (c) break; }"],
  // A ternary decides polarity by which arm holds which value. The rule declines
  // to judge that rather than guess, so a mismatch fail-fast written this way is
  // not reported — the safe direction for a gate that fails the build.
  ["ternary-inverted fail-fast", "function f(){ for (var i=0;i<n;i++) { if (b.crypto.timingSafeEqual(p,l[i]) ? false : true) return false; } }"],
  ["ternary-wrapped store", "for (var i=0;i<n;i++) { var hit = b.crypto.timingSafeEqual(p,l[i]) ? false : true; if (hit) break; }"],
];

describe("eslint rule — no-early-exit-timing-compare", function () {
  it("is exported from the canonical eslint.config.js", function () {
    assert.ok(rule, "rule must be reachable from eslint.config.js — a copy here could drift from what ships");
  });

  describe("reports a scan that stops at the first match", function () {
    FLAG.forEach(function (c) {
      it(c[0], function () {
        var msgs = lint(c[1]);
        assert.strictEqual(msgs.length, 1,
          c[0] + " must report exactly once, got " + JSON.stringify(msgs.map(function (m) { return m.message; })));
      });
    });
  });

  describe("leaves a correct scan alone", function () {
    REJECT.forEach(function (c) {
      it(c[0], function () {
        var msgs = lint(c[1]);
        assert.strictEqual(msgs.length, 0,
          c[0] + " must not be reported — a gate that fails correct code earns an allowlist entry it should never have. Got: "
          + JSON.stringify(msgs.map(function (m) { return m.message; })));
      });
    });
  });
});
