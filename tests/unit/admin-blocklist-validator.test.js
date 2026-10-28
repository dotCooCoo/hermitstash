/**
 * validateBlocklistInput stores the address in the form lib/client-ip reports
 * a client in, and refuses a spelling no client address is ever reported in.
 */
var { describe, it } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var adminValidator = require(path.join(__dirname, "..", "..", "app", "http", "validators", "admin.validator"));

describe("validateBlocklistInput", function () {
  it("accepts canonical IPv4 and IPv6 and stores the canonical IPv6 form", function () {
    assert.strictEqual(adminValidator.validateBlocklistInput({ ip: "203.0.113.7" }).ip, "203.0.113.7");
    assert.strictEqual(adminValidator.validateBlocklistInput({ ip: " 2001:DB8:0:0:0:0:0:1 " }).ip, "2001:db8::1");
  });

  it("refuses IPv4 spellings with leading zeros, out-of-range octets or other bases", function () {
    ["192.168.001.010", "010.0.0.1", "1.2.3.04", "999.1.1.1", "0x7f.0.0.1", "2130706433", "127.1"].forEach(function (ip) {
      var r = adminValidator.validateBlocklistInput({ ip: ip });
      assert.ok(r.error, ip + " is refused: " + JSON.stringify(r));
      assert.match(r.error, /^Invalid IP format\./);
    });
  });

  it("refuses non-addresses", function () {
    ["", "not-an-ip", "::g", "1.2.3", "a".repeat(46)].forEach(function (ip) {
      assert.ok(adminValidator.validateBlocklistInput({ ip: ip }).error, JSON.stringify(ip));
    });
  });
});
