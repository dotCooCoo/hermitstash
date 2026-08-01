// F-3 regression: the Resend daily/monthly quota must count ONLY Resend-backend
// rows. In a smtp+resend combo, SMTP sends (backend "smtp") were counted toward
// the Resend cap, so a burst of SMTP mail could exhaust the Resend fallback quota
// and block the fallback exactly when SMTP was failing.
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-email-quota-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

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

before(async function () { await vault.init(); });

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

function clearSends() {
  db.emailSends.find({}).forEach(function (s) { db.emailSends.remove({ _id: s._id }); });
}

describe("email quota counts only Resend-backend rows (F-3)", function () {
  it("SMTP sends do not consume the Resend quota", function () {
    clearSends();
    var now = new Date().toISOString();
    // A smtp+resend combo where SMTP is doing most of the work.
    db.emailSends.insert({ recipient: "a@example.com", subject: "s", backend: "smtp", status: "sent", createdAt: now });
    db.emailSends.insert({ recipient: "b@example.com", subject: "s", backend: "smtp", status: "sent", createdAt: now });
    db.emailSends.insert({ recipient: "c@example.com", subject: "s", backend: "resend", status: "sent", createdAt: now });
    db.emailSends.insert({ recipient: "d@example.com", subject: "s", backend: "resend", status: "pending", createdAt: now });

    var counts = email.getQuotaCounts();
    // Only the 2 resend rows (1 sent + 1 pending) count — not the 2 smtp rows.
    assert.strictEqual(counts.daily, 2, "only Resend rows count toward the daily Resend quota");
    assert.strictEqual(counts.monthly, 2, "only Resend rows count toward the monthly Resend quota");
  });

  it("a pure-SMTP run consumes zero Resend quota", function () {
    clearSends();
    var now = new Date().toISOString();
    db.emailSends.insert({ recipient: "x@example.com", subject: "s", backend: "smtp", status: "sent", createdAt: now });
    db.emailSends.insert({ recipient: "y@example.com", subject: "s", backend: "smtp", status: "pending", createdAt: now });

    var counts = email.getQuotaCounts();
    assert.strictEqual(counts.daily, 0, "SMTP-only sends must not consume Resend quota");
    assert.strictEqual(counts.monthly, 0, "SMTP-only sends must not consume Resend quota");
  });

  it("SMTP volume can no longer block the Resend fallback via the cap", function () {
    clearSends();
    config.email.backend = "smtp+resend";
    config.email.resendQuotaDaily = 3;
    config.email.resendQuotaMonthly = 1000;
    var now = new Date().toISOString();
    // Ten SMTP sends — would have overrun a cap of 3 under the old counting.
    for (var i = 0; i < 10; i++) {
      db.emailSends.insert({ recipient: "smtp" + i + "@example.com", subject: "s", backend: "smtp", status: "sent", createdAt: now });
    }
    var result = email.checkQuota({ backend: "resend" });
    assert.strictEqual(result.allowed, true, "Resend fallback stays available despite heavy SMTP volume");

    config.email.backend = "smtp";
    config.email.resendQuotaDaily = 100;
    config.email.resendQuotaMonthly = 3000;
  });
});
