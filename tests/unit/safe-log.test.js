const { describe, it } = require("node:test");
const assert = require("node:assert");

// lib/safe-log is a pure helper (no vault/db state) — require directly.
const safeLog = require("../../lib/safe-log");

describe("safe-log", function () {
  describe("scrub", function () {
    it("redacts a bearer token embedded in a message", function () {
      assert.ok(!/abcdef123456/.test(safeLog.scrub("failed with Bearer abcdef123456 token")));
    });

    it("redacts URL userinfo credentials", function () {
      assert.ok(!/s3cretpw/.test(safeLog.scrub("connect to https://user:s3cretpw@host/db failed")));
    });

    it("redacts an AWS access key id", function () {
      assert.ok(!/AKIAIOSFODNN7EXAMPLE/.test(safeLog.scrub("key AKIAIOSFODNN7EXAMPLE denied")));
    });

    it("leaves a structural crypto/fs error message intact (no over-redaction)", function () {
      var s = "Passphrase rejected or wrapped file corrupted";
      assert.strictEqual(safeLog.scrub(s), s);
    });

    it("coerces null / undefined / non-string to a string and never throws", function () {
      assert.strictEqual(safeLog.scrub(null), "");
      assert.strictEqual(safeLog.scrub(undefined), "");
      assert.strictEqual(safeLog.scrub(42), "42");
    });

    it("does NOT claim to catch raw high-entropy key bytes (documented limitation)", function () {
      // redactText deliberately excludes the entropy detector, so a raw key-byte
      // snippet passes through — which is exactly why the key-PARSE sites log only
      // safeLog.code(e), never the message. This test pins that contract so a future
      // reader does not mistakenly route a key-parse error through scrub().
      var raw = "MIIJKgIBAAKCAQEA1234567890abcdef";
      assert.ok(safeLog.scrub("bad key: " + raw).indexOf(raw) !== -1);
    });
  });

  describe("code", function () {
    it("prefers err.code", function () {
      assert.strictEqual(safeLog.code({ code: "vault/key-corrupt", name: "Error" }), "vault/key-corrupt");
    });

    it("falls back to err.name when there is no code", function () {
      assert.strictEqual(safeLog.code(new TypeError("boom")), "TypeError");
    });

    it("returns 'unknown' for null / empty object", function () {
      assert.strictEqual(safeLog.code(null), "unknown");
      assert.strictEqual(safeLog.code({}), "unknown");
    });

    it("never returns the error message — no secret can leak through code()", function () {
      var e = new Error("MIIJSECRETKEYBYTES");
      var c = safeLog.code(e);
      assert.ok(!/MIIJSECRETKEYBYTES/.test(c));
      assert.strictEqual(c, "Error");
    });
  });
});
