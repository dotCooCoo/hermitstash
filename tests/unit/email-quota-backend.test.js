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

describe("email quota — when the cap applies and when it bites", function () {
  var savedBackend, savedDaily, savedMonthly;

  before(function () {
    savedBackend = config.email.backend;
    savedDaily = config.email.resendQuotaDaily;
    savedMonthly = config.email.resendQuotaMonthly;
  });
  after(function () {
    config.email.backend = savedBackend;
    config.email.resendQuotaDaily = savedDaily;
    config.email.resendQuotaMonthly = savedMonthly;
    clearSends();
  });

  function fillResend(n) {
    var now = new Date().toISOString();
    for (var i = 0; i < n; i++) {
      db.emailSends.insert({ recipient: "r" + i + "@example.com", subject: "s", backend: "resend", status: "sent", createdAt: now });
    }
  }

  it("refuses a Resend attempt once the daily cap is reached, and says the numbers", function () {
    clearSends();
    config.email.resendQuotaDaily = 3;
    config.email.resendQuotaMonthly = 1000;
    fillResend(3);

    var res = email.checkQuota({ backend: "resend" });
    assert.strictEqual(res.allowed, false, "at the cap, not one over it");
    assert.match(res.reason, /Daily quota exceeded \(3\/3\)/,
      "the operator needs the numbers to act on: " + res.reason);
  });

  it("refuses on the monthly cap even when the day is quiet", function () {
    clearSends();
    config.email.resendQuotaDaily = 1000;
    config.email.resendQuotaMonthly = 2;
    fillResend(2);

    var res = email.checkQuota({ backend: "resend" });
    assert.strictEqual(res.allowed, false);
    assert.match(res.reason, /Monthly quota exceeded \(2\/2\)/, res.reason);
  });

  it("lets the last slot through", function () {
    clearSends();
    config.email.resendQuotaDaily = 3;
    config.email.resendQuotaMonthly = 1000;
    fillResend(2);

    var res = email.checkQuota({ backend: "resend" });
    assert.strictEqual(res.allowed, true, "two of three used means one left");
    assert.strictEqual(res.daily, 2);
  });

  it("does not apply to an SMTP attempt, however full the Resend quota is", function () {
    clearSends();
    config.email.resendQuotaDaily = 1;
    config.email.resendQuotaMonthly = 1;
    fillResend(50);

    var res = email.checkQuota({ backend: "smtp" });
    assert.strictEqual(res.allowed, true, "the cap is Resend's, so an SMTP send is not subject to it");
  });

  describe("with no concrete backend named — the admin widget's view", function () {
    // The widget asks without naming an attempt, so the answer follows the
    // configured mode. A strict equality test on "resend" used to report no cap
    // in combo modes, where Resend is very much attempted.
    it("applies in a combo mode with resend second", function () {
      clearSends();
      config.email.backend = "smtp+resend";
      config.email.resendQuotaDaily = 1;
      config.email.resendQuotaMonthly = 1000;
      fillResend(1);
      assert.strictEqual(email.checkQuota().allowed, false, "smtp+resend still routes through Resend");
    });

    it("applies in a combo mode with resend first", function () {
      clearSends();
      config.email.backend = "resend+smtp";
      config.email.resendQuotaDaily = 1;
      config.email.resendQuotaMonthly = 1000;
      fillResend(1);
      assert.strictEqual(email.checkQuota().allowed, false);
    });

    it("applies in the plain resend mode", function () {
      clearSends();
      config.email.backend = "resend";
      config.email.resendQuotaDaily = 1;
      config.email.resendQuotaMonthly = 1000;
      fillResend(1);
      assert.strictEqual(email.checkQuota().allowed, false);
    });

    it("does not apply when the mode never reaches Resend", function () {
      clearSends();
      config.email.backend = "smtp";
      config.email.resendQuotaDaily = 1;
      config.email.resendQuotaMonthly = 1;
      fillResend(50);
      assert.strictEqual(email.checkQuota().allowed, true, "no Resend in the chain, no Resend cap");
    });
  });

  it("a reservation that is withdrawn gives its slot back", function () {
    // A pending row holds a slot so a concurrent send cannot overrun the cap.
    // A send that then fails removes its row, and the slot has to return —
    // otherwise a run of failures permanently shrinks the quota.
    clearSends();
    config.email.backend = "resend";
    config.email.resendQuotaDaily = 2;
    config.email.resendQuotaMonthly = 1000;
    var now = new Date().toISOString();
    db.emailSends.insert({ recipient: "held@example.com", subject: "s", backend: "resend", status: "sent", createdAt: now });
    var pending = db.emailSends.insert({ recipient: "inflight@example.com", subject: "s", backend: "resend", status: "pending", createdAt: now });

    assert.strictEqual(email.checkQuota({ backend: "resend" }).allowed, false,
      "the in-flight reservation counts, which is what closes the race");

    db.emailSends.remove({ _id: pending._id });
    assert.strictEqual(email.checkQuota({ backend: "resend" }).allowed, true,
      "withdrawing the reservation frees the slot again");
  });
});
