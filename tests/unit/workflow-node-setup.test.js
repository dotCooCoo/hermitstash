"use strict";

/**
 * Every workflow step that runs `node` on the runner must come after the job's
 * actions/setup-node step. The runner's preinstalled Node.js is older than the
 * release HermitStash requires, and the vendored framework fails to load on it.
 * `node` run inside a container through `docker exec` is not checked.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var path = require("node:path");

var WORKFLOWS = path.join(__dirname, "..", "..", ".github", "workflows");
var NODE_CALL_RE = /(^|[\s$(;&|"'])node\s/;

function nodeBeforeSetup(text) {
  var lines = text.split(/\r?\n/);
  var hits = [];
  var job = null;
  var setup = false;
  var inRun = false;
  var runIndent = 0;
  lines.forEach(function (line, i) {
    var mJob = line.match(/^ {2}([A-Za-z0-9_-]+):\s*$/);
    if (mJob) { job = mJob[1]; setup = false; inRun = false; return; }
    if (/uses:\s*actions\/setup-node@/.test(line)) { setup = true; inRun = false; return; }
    var mRun = line.match(/^(\s*)(- )?run:\s*(.*)$/);
    if (mRun) {
      inRun = true;
      runIndent = mRun[1].length;
      if (!setup && NODE_CALL_RE.test(" " + mRun[3]) && !/docker exec/.test(mRun[3])) hits.push({ line: i + 1, job: job, text: line.trim() });
      return;
    }
    if (!inRun) return;
    var indent = line.match(/^(\s*)/)[1].length;
    if (line.trim() && indent <= runIndent) { inRun = false; return; }
    if (!setup && NODE_CALL_RE.test(line) && !/docker exec/.test(line)) hits.push({ line: i + 1, job: job, text: line.trim() });
  });
  return hits;
}

describe("workflows set up Node.js before running node", function () {
  it("flags a node call that precedes setup-node in its job", function () {
    var fixture = [
      "jobs:",
      "  build:",
      "    steps:",
      "      - name: Version",
      "        run: |",
      "          V=$(node -e \"console.log(1)\")",
      "      - uses: actions/setup-node@abc # v7.1.0",
      "      - run: node scripts/x.js",
      "  smoke:",
      "    steps:",
      "      - run: docker exec c node -e \"1\"",
    ].join("\n");
    var hits = nodeBeforeSetup(fixture);
    assert.deepStrictEqual(hits.map(function (h) { return h.job + ":" + h.line; }), ["build:6"]);
  });

  it("finds no such call in .github/workflows", function () {
    var files = fs.readdirSync(WORKFLOWS).filter(function (f) { return /\.ya?ml$/.test(f); });
    assert.ok(files.length > 0, "the workflows directory has files");
    var problems = [];
    files.forEach(function (f) {
      nodeBeforeSetup(fs.readFileSync(path.join(WORKFLOWS, f), "utf8")).forEach(function (h) {
        problems.push(f + ":" + h.line + " [" + h.job + "] " + h.text);
      });
    });
    assert.deepStrictEqual(problems, [], "run actions/setup-node before these steps");
  });
});
