/**
 * lib/runtime-floor.js: the Node.js, Brotli and OpenSSL versions server.js
 * refuses to start on.
 */
var { describe, it } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var floor = require(path.join(__dirname, "..", "..", "lib", "runtime-floor"));

function proc(node, openssl, brotli, shared) {
  return { versions: { node: node, openssl: openssl, brotli: brotli || "1.2.0" },
    config: { variables: { node_shared_brotli: !!shared } } };
}

describe("runtime-floor", function () {
  it("accepts the fixed releases on each supported line", function () {
    ["24.22.1", "24.23.0", "26.12.1", "26.13.0", "27.0.0", "28.1.2"].forEach(function (n) {
      assert.strictEqual(floor.check(proc(n, "3.5.9")), null, n);
    });
  });

  it("refuses unfixed releases, odd-numbered lines and lines before 24", function () {
    ["24.22.0", "24.21.0", "26.12.0", "26.0.0", "25.9.0", "23.11.0", "22.23.4", "20.0.0", "24.22.1-pre", "garbage"]
      .forEach(function (n) {
        var r = floor.check(proc(n, "3.5.9"));
        assert.ok(r, n + " is refused");
        assert.match(r[0], /requires Node\.js 24\.22\.1 or later on the 24 line, 26\.12\.1 or later on the 26 line/);
      });
  });

  it("checks the Brotli library version only on a shared-Brotli build", function () {
    assert.strictEqual(floor.check(proc("24.22.1", "4.0.3", "1.2.0", false)), null, "bundled decoder reports 1.2.0 after its patch");
    assert.strictEqual(floor.check(proc("24.22.1", "4.0.3", "1.2.1", true)), null);
    var r = floor.check(proc("24.22.1", "4.0.3", "1.2.0", true));
    assert.ok(r);
    assert.match(r[0], /system Brotli library 1\.2\.0/);
    var cfgString = proc("24.22.1", "4.0.3", "1.2.0", false);
    cfgString.config.variables.node_shared_brotli = "true";
    assert.ok(floor.check(cfgString), "a string 'true' is read as a shared build");
  });

  it("applies the OpenSSL floor of each line", function () {
    ["3.5.9", "3.5.10", "3.6.5", "4.0.3", "4.0.4", "4.1.0", "4.2.0", "3.7.0", "OpenSSL 3.5.9", "3.5.9+quic"].forEach(function (s) {
      assert.strictEqual(floor.check(proc("24.22.1", s)), null, s);
    });
    ["3.5.8", "3.6.4", "4.0.2", "3.4.8", "3.0.13+quic", "1.1.1w", "3.5.9-dev", "", "x"].forEach(function (s) {
      var r = floor.check(proc("24.22.1", s));
      assert.ok(r, JSON.stringify(s) + " is refused");
      assert.match(r[0], /requires OpenSSL 3\.5\.9, 3\.6\.5 or 4\.0\.3 or later/);
    });
  });

  it("passes the running test process's own runtime", function () {
    assert.strictEqual(floor.check(process), null,
      "this test runs on Node " + process.versions.node + " / OpenSSL " + process.versions.openssl);
  });
});
