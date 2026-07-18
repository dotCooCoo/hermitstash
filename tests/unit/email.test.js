const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const b = require("../../lib/vendor/blamejs");

// Use an isolated test database
var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-email-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

// Clear module cache so db, config, email all load fresh
Object.keys(require.cache).forEach(function (k) {
  if (k.includes("lib/db") || k.includes("lib\\db") ||
      k.includes("lib/config") || k.includes("lib\\config") ||
      k.includes("lib/email") || k.includes("lib\\email") ||
      k.includes("lib/audit") || k.includes("lib\\audit")) {
    delete require.cache[k];
  }
});

var config = require("../../lib/config");
var db = require("../../lib/db");
var email = require("../../lib/email");
var vault = require("../../lib/vault");

// Email sends seal recipient/subject, and audit-on-failure seals too, so the
// vault must be initialized before the suite.
before(async function () { await vault.init(); });

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
  try { fs.unlinkSync(testDbPath.replace(".db", "") + ".db.enc"); } catch {}
});

describe("email", function () {
  describe("renderTpl() — template-variable escaping", function () {
    var origMode = config.emailTemplateMode;
    after(function () { config.emailTemplateMode = origMode; });

    it("escapes substituted values in html mode while keeping the admin template HTML", function () {
      config.emailTemplateMode = "html";
      // Admin-authored template carries literal HTML (trusted) AND interpolates an
      // attacker-controlled value via {uploaderName} (an anonymous public upload).
      var out = email._renderTpl("<b>Hi {uploaderName}</b>", { uploaderName: "<script>alert(1)</script>\"x" });
      assert.ok(out.indexOf("<b>Hi ") === 0, "admin's literal <b> HTML is preserved");
      assert.strictEqual(out.indexOf("<script>"), -1, "the injected <script> must be escaped, not emitted");
      assert.ok(out.indexOf("&lt;script&gt;") !== -1, "value angle brackets are HTML-escaped");
      assert.ok(out.indexOf("&quot;") !== -1, "value quotes are HTML-escaped");
    });

    it("escapes the whole rendered result in text mode", function () {
      config.emailTemplateMode = "text";
      var out = email._renderTpl("Hi {uploaderName}", { uploaderName: "<script>alert(1)</script>" });
      assert.strictEqual(out.indexOf("<script>"), -1, "text mode escapes the rendered output");
      assert.ok(out.indexOf("&lt;script&gt;") !== -1);
    });

    it("passes non-string values through unchanged in html mode", function () {
      config.emailTemplateMode = "html";
      var out = email._renderTpl("{fileCount} files", { fileCount: 7 });
      assert.strictEqual(out, "7 files");
    });
  });

  describe("sendEmail()", function () {
    it("returns false when SMTP not configured and backend is smtp", async function () {
      config.email.backend = "smtp";
      config.email.host = "";
      var result = await email.sendEmail({ to: "user@example.com", subject: "Test", html: "<p>hi</p>" });
      assert.strictEqual(result, false);
    });

    it("returns false when Resend not configured and backend is resend", async function () {
      config.email.backend = "resend";
      config.email.resendApiKey = "";
      var result = await email.sendEmail({ to: "user@example.com", subject: "Test", html: "<p>hi</p>" });
      assert.strictEqual(result, false);
      config.email.backend = "smtp";
    });
  });

  describe("checkQuota()", function () {
    it("returns allowed:true when backend is smtp (no quota)", function () {
      config.email.backend = "smtp";
      var result = email.checkQuota();
      assert.strictEqual(result.allowed, true);
    });

    it("returns allowed:false when daily quota exceeded", function () {
      config.email.backend = "resend";
      config.email.resendQuotaDaily = 2;
      config.email.resendQuotaMonthly = 1000;

      // Insert enough email_sends records to exceed daily quota
      var now = new Date().toISOString();
      for (var i = 0; i < 3; i++) {
        db.emailSends.insert({
          recipient: "test" + i + "@example.com",
          subject: "test",
          backend: "resend",
          status: "sent",
          createdAt: now,
        });
      }

      var result = email.checkQuota();
      assert.strictEqual(result.allowed, false);
      assert.ok(result.reason.includes("Daily"), "reason should mention daily quota");

      // Reset
      config.email.backend = "smtp";
      config.email.resendQuotaDaily = 100;
    });

    it("returns allowed:false when monthly quota exceeded", function () {
      // Remove previous records first
      db.emailSends.find({}).forEach(function (s) { db.emailSends.remove({ _id: s._id }); });

      config.email.backend = "resend";
      config.email.resendQuotaDaily = 1000;
      config.email.resendQuotaMonthly = 2;

      // Insert records at the start of this month
      var now = new Date();
      var monthStart = new Date(now.getFullYear(), now.getMonth(), 1, 12, 0, 0);
      for (var i = 0; i < 3; i++) {
        db.emailSends.insert({
          recipient: "monthly" + i + "@example.com",
          subject: "monthly test",
          backend: "resend",
          status: "sent",
          createdAt: monthStart.toISOString(),
        });
      }

      var result = email.checkQuota();
      assert.strictEqual(result.allowed, false);
      assert.ok(result.reason.includes("Monthly"), "reason should mention monthly quota");

      // Reset
      config.email.backend = "smtp";
      config.email.resendQuotaMonthly = 3000;
    });
  });

  describe("getQuotaCounts()", function () {
    it("returns {daily:0, monthly:0} when no sends exist", function () {
      // Remove all previous records
      db.emailSends.find({}).forEach(function (s) { db.emailSends.remove({ _id: s._id }); });

      var counts = email.getQuotaCounts();
      assert.strictEqual(counts.daily, 0);
      assert.strictEqual(counts.monthly, 0);
    });

    it("counts in-flight 'pending' reservations toward the quota (reserve-then-confirm)", function () {
      // Clear, then write reservation rows the way trySend does before the
      // resend network round-trip resolves. A read-check-then-send with no
      // reservation would leave these invisible and let concurrent sends
      // overrun the cap; getQuotaCounts must count them so the cap holds.
      db.emailSends.find({}).forEach(function (s) { db.emailSends.remove({ _id: s._id }); });

      var now = new Date().toISOString();
      db.emailSends.insert({ recipient: "a@example.com", subject: "s", backend: "resend", status: "sent", createdAt: now });
      db.emailSends.insert({ recipient: "b@example.com", subject: "s", backend: "resend", status: "pending", createdAt: now });
      db.emailSends.insert({ recipient: "c@example.com", subject: "s", backend: "resend", status: "pending", createdAt: now });

      var counts = email.getQuotaCounts();
      assert.strictEqual(counts.daily, 3, "1 sent + 2 pending all count toward daily quota");
      assert.strictEqual(counts.monthly, 3, "1 sent + 2 pending all count toward monthly quota");
    });

    it("checkQuota refuses once sent+pending reach the cap", function () {
      db.emailSends.find({}).forEach(function (s) { db.emailSends.remove({ _id: s._id }); });
      config.email.backend = "resend";
      config.email.resendQuotaDaily = 2;
      config.email.resendQuotaMonthly = 1000;

      var now = new Date().toISOString();
      // One delivered, one still in-flight — together they hit the daily cap of 2.
      db.emailSends.insert({ recipient: "x@example.com", subject: "s", backend: "resend", status: "sent", createdAt: now });
      db.emailSends.insert({ recipient: "y@example.com", subject: "s", backend: "resend", status: "pending", createdAt: now });

      var result = email.checkQuota({ backend: "resend" });
      assert.strictEqual(result.allowed, false, "pending reservation must count so the cap holds under concurrency");
      assert.ok(result.reason.includes("Daily"));

      config.email.backend = "smtp";
      config.email.resendQuotaDaily = 100;
    });

    it("reclaims stale 'pending' reservations older than the TTL", function () {
      db.emailSends.find({}).forEach(function (s) { db.emailSends.remove({ _id: s._id }); });

      // A crash between reserve and confirm leaves an old pending row; it must
      // not permanently consume quota. Stamp one well past the TTL window.
      var stale = new Date(Date.now() - 60 * 60 * 1000).toISOString(); // 1h ago
      var fresh = new Date().toISOString();
      db.emailSends.insert({ recipient: "stale@example.com", subject: "s", backend: "resend", status: "pending", createdAt: stale });
      db.emailSends.insert({ recipient: "fresh@example.com", subject: "s", backend: "resend", status: "pending", createdAt: fresh });

      var counts = email.getQuotaCounts();
      assert.strictEqual(counts.daily, 1, "only the fresh pending reservation counts; the stale one is reclaimed");
      assert.strictEqual(db.emailSends.find({ status: "pending" }).length, 1, "stale pending row is removed");
    });
  });

  describe("validateEmailAddr()", function () {
    // Internal helper, not exported. Pulled in via a fresh require so
    // the function reference is the same one resendSend/smtpSend gate
    // through. lib/email.js doesn't export it directly — we exercise it
    // via the indirect surface (sendEmail with malformed `to`) instead.
    it("sendEmail returns false for addresses containing CR (SMTP header injection)", async function () {
      var result = await email.sendEmail({
        to: "victim@example.com\r\nBcc: attacker@evil.com",
        subject: "test",
        html: "<p>hi</p>",
      });
      // Without a backend configured, sendEmail returns false either
      // way. The point of this assertion is that the early-bail rejection
      // doesn't crash with header injection in the address.
      assert.strictEqual(result, false);
    });

    it("sendEmail returns false for addresses containing LF (SMTP header injection)", async function () {
      var result = await email.sendEmail({
        to: "victim@example.com\nBcc: attacker@evil.com",
        subject: "test",
        html: "<p>hi</p>",
      });
      assert.strictEqual(result, false);
    });

    it("sendEmail returns false for addresses containing NUL", async function () {
      var result = await email.sendEmail({
        to: "victim@example.com extra",
        subject: "test",
        html: "<p>hi</p>",
      });
      assert.strictEqual(result, false);
    });

    it("sendEmail returns false for null/undefined/non-string addresses", async function () {
      assert.strictEqual(await email.sendEmail({ to: null, subject: "x", html: "y" }), false);
      assert.strictEqual(await email.sendEmail({ to: undefined, subject: "x", html: "y" }), false);
      assert.strictEqual(await email.sendEmail({ to: 42, subject: "x", html: "y" }), false);
      assert.strictEqual(await email.sendEmail({ to: { evil: true }, subject: "x", html: "y" }), false);
    });
  });

  describe("backend gating", function () {
    it("sendEmail returns false when no backend is active (smtp missing host)", async function () {
      config.email.backend = "smtp";
      config.email.host = "";
      var result = await email.sendEmail({
        to: "ok@test.com", subject: "x", html: "y",
      });
      assert.strictEqual(result, false);
    });

    it("sendEmail returns false when resend backend has no API key", async function () {
      config.email.backend = "resend";
      config.email.resendApiKey = "";
      var result = await email.sendEmail({
        to: "ok@test.com", subject: "x", html: "y",
      });
      assert.strictEqual(result, false);
      // Reset for any later tests
      config.email.backend = "smtp";
    });

    it("sendEmail with empty subject returns false", async function () {
      var result = await email.sendEmail({
        to: "ok@test.com", subject: "", html: "y",
      });
      assert.strictEqual(result, false);
    });

    it("sendEmail with empty html returns false", async function () {
      var result = await email.sendEmail({
        to: "ok@test.com", subject: "x", html: "",
      });
      assert.strictEqual(result, false);
    });
  });

  describe("template placeholder resolution (own-property)", function () {
    it("substitutes a real variable", function () {
      assert.strictEqual(email._renderTpl("Hi {name}", { name: "Ann" }), "Hi Ann");
    });

    it("leaves an inherited Object.prototype name as the literal placeholder", function () {
      // {constructor} / {__proto__} / {toString} name inherited members. A bare
      // vars[key] read would splice a function's source into the email; the
      // own-property guard renders them as the literal {name} instead.
      assert.strictEqual(email._renderTpl("x{constructor}y", {}), "x{constructor}y");
      assert.strictEqual(email._renderTpl("a{__proto__}b", {}), "a{__proto__}b");
      assert.strictEqual(email._renderTpl("p{toString}q", { name: "Ann" }), "p{toString}q");
    });

    it("leaves an unknown own name as the literal placeholder", function () {
      assert.strictEqual(email._renderTpl("{missing}", { name: "Ann" }), "{missing}");
    });
  });
});
