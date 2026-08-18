"use strict";

/**
 * The composed message must survive the values that get interpolated into it.
 *
 * Two separate concerns, both in lib/email.js.
 *
 * The button's href is the one value in these templates that is computed rather
 * than written literally, and it lands inside a quoted HTML attribute. Every
 * caller today passes getOrigin() plus a server-generated token, and getOrigin
 * reads operator configuration rather than the request's Host header — so
 * nothing an attacker controls reaches it. That is a property of the callers,
 * and the sort that changes quietly: a URL built from a slug or a display name,
 * with a quote in it, would close the attribute and let the remainder into the
 * message. The escaping is asserted here so the sink stays defended whatever the
 * callers do later.
 *
 * The public send functions compose their bodies BEFORE any backend is
 * consulted, so their template code runs on every call — including the calls
 * where a caller omitted an optional field. A missing uploader name, an absent
 * file list or a zero count must not throw: these are called from upload
 * handling and from the account routes, where an exception is a failed request
 * rather than a missing email.
 */

require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");

var config = require("../../lib/config");
var email = require("../../lib/email");
var vault = require("../../lib/vault");

// Sealing runs on the tracking row every send writes, so the vault has to be up.
before(async function () { await vault.init(); });

var savedBackend, savedHost, savedKey;
before(function () {
  savedBackend = config.email.backend;
  savedHost = config.email.host;
  savedKey = config.email.resendApiKey;
  // No backend configured: every send returns false without touching a network,
  // and the body is still composed on the way there, which is the code under test.
  config.email.backend = "smtp";
  config.email.host = "";
  config.email.resendApiKey = "";
});
after(function () {
  config.email.backend = savedBackend;
  config.email.host = savedHost;
  config.email.resendApiKey = savedKey;
});

// The attribute value, and what a parser reads it back as. Asserting the
// round-trip rather than one escaper's exact output: the property that matters
// is "the link still points where it did, and nothing escaped the quotes", and
// that holds whichever escaper is in use.
function hrefOf(html) {
  var m = /<a href="([^"]*)"/.exec(html);
  return m ? m[1] : null;
}
function decodeAttr(v) {
  return String(v)
    .replace(/&#x([0-9a-fA-F]+);/g, function (_, h) { return String.fromCodePoint(parseInt(h, 16)); })
    .replace(/&quot;/g, "\"").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");   // last, so an encoded &amp;amp; is not over-decoded
}

describe("the button href cannot break out of its attribute", function () {
  it("a reader still follows the URL that was passed in", function () {
    ["https://stash.example.com/auth/verify/abc-123_XYZ",
      "https://stash.example.com/b/AbC?x=1&y=2",
      "https://stash.example.com/r/tok#frag"].forEach(function (url) {
      var raw = hrefOf(email._emailButton("Open", url));
      assert.ok(raw !== null, "the button must render one quoted href");
      assert.strictEqual(decodeAttr(raw), url,
        "the escaped attribute must decode back to exactly the URL passed in");
    });
  });

  it("a quote in the URL cannot end the attribute and open an event handler", function () {
    var html = email._emailButton("Verify", 'https://x.example/" onmouseover="alert(1)');
    assert.strictEqual(html.indexOf('" onmouseover="'), -1,
      "the quote must not survive raw: " + html);
    var raw = hrefOf(html);
    assert.strictEqual(raw.indexOf("\""), -1, "no bare quote may remain inside the attribute");
    assert.ok(/&quot;|&#x22;/.test(raw), "it must be encoded instead: " + raw);
  });

  it("a backtick is encoded too, which an unquoted-attribute slip would expose", function () {
    var raw = hrefOf(email._emailButton("Open", "https://x.example/a`b"));
    assert.strictEqual(raw.indexOf("`"), -1, raw);
  });

  it("renders an absent URL as an empty attribute rather than the word undefined", function () {
    assert.strictEqual(hrefOf(email._emailButton("Open", undefined)), "");
    assert.strictEqual(hrefOf(email._emailButton("Open", null)), "");
  });
});

describe("the send functions refuse a missing recipient before composing", function () {
  // Each guards on `to` first. The guard is what stops a caller with no address
  // from reaching the backend at all.
  var CASES = [
    ["sendVerificationEmail", { displayName: "Ann", verifyUrl: "https://x.example/v/1" }],
    ["sendInviteEmail", { inviteUrl: "https://x.example/i/1", inviterName: "Ann", role: "member" }],
    ["sendPasswordResetEmail", { resetUrl: "https://x.example/r/1" }],
    ["sendBundleAccessCode", { code: "123456", bundleName: "b", senderName: "Ann" }],
    ["sendUploaderConfirmation", { uploadedCount: 1, uploadedFiles: [], totalSize: 1 }],
  ];
  CASES.forEach(function (pair) {
    it(pair[0] + " returns false with no recipient", async function () {
      var args = Object.assign({}, pair[1]);
      assert.strictEqual(await email[pair[0]](args), false, "absent `to`");
      args.to = "";
      assert.strictEqual(await email[pair[0]](args), false, "empty `to`");
    });
  });
});

describe("composition survives the optional fields being absent", function () {
  // Every one of these returns false — no backend is configured — but it does so
  // AFTER building the message, so a template that throws on a missing value
  // fails here rather than in an upload.
  it("an upload confirmation with no file lists and no skipped files", async function () {
    var r = await email.sendUploaderConfirmation({
      to: "u@example.com", uploaderName: "Ann", bundleUrl: "https://x.example/b/1",
      uploadedCount: 2, totalSize: 2048,
    });
    assert.strictEqual(r, false);
  });

  it("an upload confirmation carrying both uploaded and skipped files", async function () {
    var r = await email.sendUploaderConfirmation({
      to: "u@example.com", uploaderName: "Ann", bundleUrl: "https://x.example/b/1",
      uploadedCount: 1, uploadedFiles: [{ path: "a/b.txt", size: 10 }],
      skippedCount: 1, skippedFiles: [{ path: "c.exe", reason: "extension not allowed" }],
      totalSize: 10,
    });
    assert.strictEqual(r, false);
  });

  it("an upload confirmation whose counts exceed the per-message caps", async function () {
    // The lists are capped at 100 uploaded and 50 skipped so one large bundle
    // cannot compose an unbounded message.
    var many = [];
    for (var i = 0; i < 250; i++) many.push({ path: "f" + i + ".bin", size: i });
    var skipped = [];
    for (var j = 0; j < 120; j++) skipped.push({ path: "s" + j + ".bin", reason: "too large" });
    var r = await email.sendUploaderConfirmation({
      to: "u@example.com", uploaderName: "Ann", bundleUrl: "https://x.example/b/1",
      uploadedCount: 250, uploadedFiles: many,
      skippedCount: 120, skippedFiles: skipped, totalSize: 999999,
    });
    assert.strictEqual(r, false);
  });

  it("an upload confirmation with nothing uploaded is refused outright", async function () {
    var r = await email.sendUploaderConfirmation({
      to: "u@example.com", uploaderName: "Ann", uploadedCount: 0, totalSize: 0,
    });
    assert.strictEqual(r, false, "no files means no message, whatever else was passed");
  });

  it("an admin notification for a single address and for several", async function () {
    // The recipient list is passed as an ARRAY on purpose: comma-joining it makes
    // one malformed address and every admin silently gets nothing.
    assert.strictEqual(await email.sendAdminNotification({
      adminEmails: "one@example.com", uploaderName: "Ann", bundleUrl: "https://x.example/b/1",
      uploadedCount: 1, skippedCount: 0, totalSize: 1,
    }), false);
    assert.strictEqual(await email.sendAdminNotification({
      adminEmails: ["one@example.com", "two@example.com"], uploaderName: "Ann",
      uploaderEmail: "ann@example.com", bundleUrl: "https://x.example/b/1",
      uploadedCount: 1, skippedCount: 2, totalSize: 1,
    }), false);
  });

  it("an admin notification for an empty upload is refused outright", async function () {
    assert.strictEqual(await email.sendAdminNotification({
      adminEmails: ["one@example.com"], uploaderName: "Ann", uploadedCount: 0,
      skippedCount: 0, totalSize: 0,
    }), false);
  });

  it("a verification email with no display name", async function () {
    assert.strictEqual(await email.sendVerificationEmail({
      to: "u@example.com", verifyUrl: "https://x.example/v/1",
    }), false);
  });

  it("an invite for each role", async function () {
    assert.strictEqual(await email.sendInviteEmail({
      to: "u@example.com", inviteUrl: "https://x.example/i/1", inviterName: "Ann", role: "admin",
    }), false);
    assert.strictEqual(await email.sendInviteEmail({
      to: "u@example.com", inviteUrl: "https://x.example/i/1", inviterName: "Ann", role: "member",
    }), false);
  });

  it("an access code with and without the optional sender and bundle name", async function () {
    assert.strictEqual(await email.sendBundleAccessCode({
      to: "u@example.com", code: "123456",
    }), false, "neither optional field");
    assert.strictEqual(await email.sendBundleAccessCode({
      to: "u@example.com", code: "123456", bundleName: "Photos", senderName: "Ann",
      expiresMinutes: 30,
    }), false, "both, plus an explicit expiry");
  });

  it("a password reset", async function () {
    assert.strictEqual(await email.sendPasswordResetEmail({
      to: "u@example.com", resetUrl: "https://x.example/r/1",
    }), false);
  });
});

describe("the send functions refuse an address carrying a header break", function () {
  // The guard is in sendEmail, but it has to hold through every public entry
  // point — these are the ones reachable from unauthenticated routes.
  var CR = "\r", LF = "\n", NUL = String.fromCharCode(0);
  [CR + "Bcc: attacker@evil.example", LF + "Bcc: attacker@evil.example", NUL + "x"]
    .forEach(function (payload, i) {
      it("case " + (i + 1) + " is refused by the access-code path", async function () {
        assert.strictEqual(await email.sendBundleAccessCode({
          to: "victim@example.com" + payload, code: "123456",
        }), false);
      });
      it("case " + (i + 1) + " is refused by the password-reset path", async function () {
        assert.strictEqual(await email.sendPasswordResetEmail({
          to: "victim@example.com" + payload, resetUrl: "https://x.example/r/1",
        }), false);
      });
    });
});
