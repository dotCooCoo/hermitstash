"use strict";

/**
 * Who a stash's email gate lets in.
 *
 * A stash set to email-gated access sends its unlock code only to addresses on
 * its allowlist, which holds exact addresses and whole domains written
 * @example.com. This is the rule that decides access, and it had no test at
 * all — including the part of it that exists specifically to close a bypass.
 *
 * The gate is deliberately unobservable from outside: /stash/:slug/request-code
 * answers "check your email" whether or not the address is allowed, so the
 * endpoint cannot be used to enumerate recipients. Asserting the rule therefore
 * means calling it, not driving HTTP.
 */

var { describe, it, after } = require("node:test");
var assert = require("node:assert");

// Before routes/stash, and before anything that reaches lib/db. Requiring the
// route pulls the database in, and lib/db decrypts and writes on load — without
// this the test would open the real data directory and operate on live state.
// test-env points it at a throwaway database as a side effect of being required.
var testEnv = require("../helpers/test-env");

// And the data directory, which test-env does not touch — so without this the
// module would read and write the real one.
var tmpDataDir = require("node:fs").mkdtempSync(require("node:path").join(require("node:os").tmpdir(), "hs-test-"));
process.env.HERMITSTASH_DATA_DIR = tmpDataDir;

var matches = require("../../routes/stash").emailMatchesAllowedList;

after(function () {
  if (testEnv && typeof testEnv.cleanup === "function") testEnv.cleanup();
  try { require("node:fs").rmSync(tmpDataDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
});

describe("stash email allowlist", function () {
  it("admits an address that is on the list", function () {
    assert.equal(matches("alice@example.com", "alice@example.com"), true);
    assert.equal(matches("alice@example.com", "bob@example.com,alice@example.com"), true);
  });

  it("refuses an address that is not", function () {
    assert.equal(matches("mallory@example.com", "alice@example.com"), false);
    assert.equal(matches("alice@example.com", ""), false);
    assert.equal(matches("alice@example.com", null), false);
  });

  it("admits any address in an allowed domain", function () {
    assert.equal(matches("anyone@example.com", "@example.com"), true);
    assert.equal(matches("someone.else@example.com", "a@b.com,@example.com"), true);
  });

  it("treats an allowed domain as that domain only, not its subdomains", function () {
    // @example.com must not admit evil.example.com. Anyone who can register a
    // subdomain under a domain they control would otherwise inherit access.
    assert.equal(matches("alice@evil.example.com", "@example.com"), false);
    assert.equal(matches("alice@example.com.evil.test", "@example.com"), false);
  });

  it("refuses an address carrying a second @", function () {
    // The bypass this guards. An address has exactly one "@" (RFC 5322 §3.4.1).
    // Read the domain from the FIRST one and "alice@evil.test@example.com"
    // looks like it belongs to evil.test while ending in an allowed domain —
    // read it from either end without rejecting the shape and some allowlist
    // entry matches something it should not.
    assert.equal(matches("alice@evil.test@example.com", "@example.com"), false);
    assert.equal(matches("alice@example.com@evil.test", "@example.com"), false);
    assert.equal(matches("a@b@c", "@c"), false);
  });

  it("refuses an address with no @ at all", function () {
    assert.equal(matches("not-an-address", "@example.com"), false);
    assert.equal(matches("", "@example.com"), false);
  });

  it("ignores case and the spacing around list entries", function () {
    assert.equal(matches("Alice@Example.COM", "alice@example.com"), true);
    assert.equal(matches("alice@example.com", " alice@example.com , bob@example.com "), true);
    assert.equal(matches("ANYONE@EXAMPLE.COM", "@Example.com"), true);
  });

  it("ignores empty entries rather than admitting on them", function () {
    // A trailing comma is the ordinary way to produce one, and an empty entry
    // that matched anything would open the gate completely.
    assert.equal(matches("mallory@elsewhere.test", "alice@example.com,,"), false);
    assert.equal(matches("mallory@elsewhere.test", ",,,"), false);
  });
});
