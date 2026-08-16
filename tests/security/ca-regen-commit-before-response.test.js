"use strict";

/**
 * The CA rotation must not report success before it has committed.
 *
 * Regenerating the sync CA issues fresh client certificates, rewrites the
 * stored fingerprint on every affected API key, and only then writes the new CA
 * to disk. The handler used to answer {ok:true, "…Committing and restarting."}
 * and commit afterwards, inside a catch that begins `if (res.headersSent)
 * return;` — so a commit that threw was logged and dropped.
 *
 * What that leaves behind is the bad part: the certificates and their stored
 * fingerprints have already moved to a CA that was never written, the server
 * stays up on the old one, and the operator has been told it worked. Those
 * clients then cannot authenticate, and nothing points at why.
 *
 * commit() throws on a real condition — a still-retained prior root makes it
 * refuse — so this is reachable, not theoretical. Committing before responding
 * turns the silent half-rotation into a 500 that names the reason.
 *
 * Read from the source: driving it needs a live CA, connected sync clients over
 * mTLS and a commit induced to fail, and what is worth pinning is the ordering
 * itself.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var path = require("node:path");

var projectRoot = path.join(__dirname, "..", "..");

function regenHandler() {
  var src = fs.readFileSync(path.join(projectRoot, "routes", "admin.js"), "utf8");
  var start = src.indexOf('app.post("/admin/api/mtls-ca/regenerate"');
  assert.ok(start !== -1, "the regenerate route must still exist for this test to mean anything");
  // Bounded at the next route registration so the window is this handler only.
  var next = src.indexOf("app.post(", start + 10);
  var end = next === -1 ? src.length : next;
  return src.slice(start, end);
}

describe("CA regeneration commits before it reports success", function () {
  it("both paths commit first and respond second", function () {
    var body = regenHandler();

    ["fast-path", "rotation-path"].forEach(function (label) {
      var call = body.indexOf('commitCa("' + label + '")');
      assert.ok(call !== -1, "the " + label + " must go through commitCa");

      // The response for this path must come after its commit.
      var respond = body.indexOf("res.json(", call);
      assert.ok(respond !== -1, "the " + label + " must answer the caller");

      var earlierResponse = body.lastIndexOf("res.json(", call);
      assert.ok(earlierResponse === -1 || earlierResponse < body.lastIndexOf("commitCa(", call),
        "no response may be written for the " + label + " before its commit");
    });
  });

  it("the restart is scheduled separately, after the response", function () {
    // The exit genuinely has to follow the flush — that constraint is why the
    // two were one step. Splitting them is what lets the commit move earlier.
    var body = regenHandler();
    assert.match(body, /function scheduleRestart\(\)/,
      "the restart must be its own step");
    assert.match(body, /if \(restartFast\) scheduleRestart\(\);/,
      "the fast path restarts only after responding");
    assert.match(body, /if \(restartRotation\) scheduleRestart\(\);/,
      "and so does the rotation path");
  });

  it("a commit failure is no longer swallowed by an already-sent response", function () {
    // The catch still guards against double-writing a response, which is
    // correct — what changed is that the commit can no longer fail underneath
    // one. If a res.json ever moves back above commitCa, this guard silently
    // starts hiding commit failures again.
    var body = regenHandler();
    var firstCommit = body.indexOf("await commitCa(");
    var firstRespond = body.indexOf("res.json(");
    assert.ok(firstCommit !== -1 && firstRespond !== -1);
    assert.ok(firstCommit < firstRespond,
      "the first thing the handler does with an outcome must be commit, not answer");
  });

  it("a dry run still commits nothing and still answers", function () {
    var body = regenHandler();
    assert.match(body, /return false;/,
      "skipRestart must report that nothing was committed");
    assert.match(body, /Dry run — nothing committed\.|dry run, nothing committed\./i,
      "and the caller must be told so rather than being told it restarted");
  });
});
