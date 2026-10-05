/**
 * The sync CA (lib/mtls-ca.js) and the browser CA (lib/mtls-ca-browser.js) are
 * two b.mtlsCa handles in one data directory. Every file a handle reads or
 * writes must have a different path for each CA, including files a framework
 * release adds later with a default name.
 */
var scratch = require("../helpers/isolate-db"); // must precede every HermitStash require
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var { describe, it } = require("node:test");
var assert = require("node:assert");

var DATA_DIR = nodePath.join(scratch.dir, "data");
nodeFs.mkdirSync(DATA_DIR, { recursive: true });
process.env.HERMITSTASH_DATA_DIR = DATA_DIR;

var mtlsCa = require("../../lib/mtls-ca");
var mtlsCaBrowser = require("../../lib/mtls-ca-browser");

describe("mTLS CA on-disk artifacts", function () {
  it("the browser CA uses a different path for every file the sync CA uses", function () {
    var keys = Object.keys(mtlsCa.paths);
    assert.ok(keys.length > 0, "the sync CA handle exposes its resolved paths");
    var shared = keys.filter(function (k) { return mtlsCaBrowser.paths[k] === mtlsCa.paths[k]; });
    assert.deepStrictEqual(shared, [], "paths both CAs use: " + shared.join(", "));
  });

  it("both CAs resolve every artifact inside the data directory", function () {
    [mtlsCa, mtlsCaBrowser].forEach(function (ca) {
      Object.keys(ca.paths).forEach(function (k) {
        assert.strictEqual(nodePath.dirname(ca.paths[k]), DATA_DIR, k + " resolves under the data directory");
      });
    });
  });
});
