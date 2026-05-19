"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("b.mail.journal.create is a function",
    typeof b.mail.journal.create === "function");
  check("REGIME_FLOOR_MS table exported",
    typeof b.mail.journal.REGIME_FLOOR_MS === "object" &&
    typeof b.mail.journal.REGIME_FLOOR_MS["sec-17a-4"] === "number");
  check("SEC 17a-4 floor = 6 years",
    b.mail.journal.REGIME_FLOOR_MS["sec-17a-4"] === b.constants.TIME.days(365 * 6));
  check("MiFID II floor = 5 years",
    b.mail.journal.REGIME_FLOOR_MS["mifid-ii"] === b.constants.TIME.days(365 * 5));
  check("SOX floor = 7 years",
    b.mail.journal.REGIME_FLOOR_MS["sox"] === b.constants.TIME.days(365 * 7));
}

function testBadInput() {
  function expectThrow(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-journal/") === 0);
  }
  expectThrow("refuses missing opts",
    function () { b.mail.journal.create(); });
  expectThrow("refuses non-bucket-ops storage",
    function () { b.mail.journal.create({ storage: {} }); });
  expectThrow("refuses missing regimes",
    function () { b.mail.journal.create({
      storage: { putObject: function () {} },
      vault:   { seal: function () {} },
      legalHold: { isOnHold: function () {} },
      db: { runSql: function () {} },
    }); });
  expectThrow("refuses unknown regime",
    function () { b.mail.journal.create({
      storage:   { putObject: function () {} },
      vault:     { seal: function () {} },
      legalHold: { isOnHold: function () {} },
      db:        { runSql: function () {} },
      regimes:   ["bogus-regime"],
    }); });
  expectThrow("refuses bad namespace",
    function () { b.mail.journal.create({
      storage:   { putObject: function () {} },
      vault:     { seal: function () {} },
      legalHold: { isOnHold: function () {} },
      db:        { runSql: function () {} },
      regimes:   ["hipaa"],
      namespace: "bad/slash",
    }); });
}

function testRegimeFloorMath() {
  // create() computes the longest floor across declared regimes
  var storage = {
    putObject: async function () { return { ok: true }; },
    getObject: async function () { return null; },
    listObjects: async function () { return []; },
  };
  var calls = [];
  var db = { runSql: function (sql, args) { calls.push({ sql: sql.slice(0, 40), args: args }); return []; } };
  var vault     = { seal: function (x) { return x; } };
  var legalHold = { isOnHold: function () { return false; } };

  var j = b.mail.journal.create({
    storage: storage, vault: vault, legalHold: legalHold, db: db,
    regimes: ["sec-17a-4", "mifid-ii"],  // 6yr + 5yr → 6yr
    namespace: "test1",
  });
  check("floor = max across regimes (SEC 6yr wins over MiFID 5yr)",
    j.floorMs === b.constants.TIME.days(365 * 6));

  var j2 = b.mail.journal.create({
    storage: storage, vault: vault, legalHold: legalHold, db: db,
    regimes: ["sox", "hipaa"],  // 7yr + 6yr → 7yr
    namespace: "test2",
  });
  check("floor = max across regimes (SOX 7yr wins over HIPAA 6yr)",
    j2.floorMs === b.constants.TIME.days(365 * 7));
}

function testCreatesIndexTable() {
  var ddlSeen = [];
  var db = {
    runSql: function (sql) {
      if (/CREATE TABLE|CREATE INDEX/.test(sql)) ddlSeen.push(sql);
      return [];
    },
  };
  b.mail.journal.create({
    storage:   { putObject: async function () {} },
    vault:     { seal: function () {} },
    legalHold: { isOnHold: function () { return false; } },
    db:        db,
    regimes:   ["hipaa"],
    namespace: "compliance",
  });
  check("CREATE TABLE issued at create()",
    ddlSeen.length === 1 && /_mail_journal_compliance/.test(ddlSeen[0]));
  check("CREATE INDEX includes archived_at + message_id",
    /_archived_at_idx/.test(ddlSeen[0]) && /_message_id_idx/.test(ddlSeen[0]));
}

function testIndexNamesValidSql() {
  // Regression for Codex P1: index names must be built from the
  // unquoted base then quoted independently — appending suffixes to
  // an already-quoted token produces invalid SQL like
  // `"_mail_journal_x"_archived_at_idx`.
  var ddlSeen = [];
  var db = {
    runSql: function (sql) {
      ddlSeen.push(sql);
      return [];
    },
  };
  b.mail.journal.create({
    storage:   { putObject: async function () {} },
    vault:     { seal: function () {} },
    legalHold: { isOnHold: function () { return false; } },
    db:        db,
    regimes:   ["hipaa"],
    namespace: "compliance",
  });
  var sql = ddlSeen[0];
  // Index lines must look like: CREATE INDEX IF NOT EXISTS "<idx_name>" ON "<table_name>" (...)
  // — quoted IDX name followed by quoted TABLE name. The bug shape is
  // `"<table>"_idx_suffix` (suffix appended after the closing quote).
  check("index names not appended to quoted table name",
    !/"_mail_journal_compliance"_/.test(sql));
  check("archived_at index has quoted IDX name", /"_mail_journal_compliance_archived_at_idx"/.test(sql));
  check("message_id  index has quoted IDX name", /"_mail_journal_compliance_message_id_idx"/.test(sql));
}

function testSealUnsealRoundTrip() {
  // Regression for two Codex P1s: vault.seal / vault.unseal are the
  // correct primitives (not cryptoField.sealRow which expects a
  // schema-registered table). Round-trip the payload through a fake
  // vault that returns a deterministic JSON of its input.
  var fakeVault = {
    seal:   function (s) { return "vault:" + s; },
    unseal: function (s) { return s.slice("vault:".length); },
  };
  var putCalls = [];
  var insertedRow = null;
  var storage = {
    putObject: async function (key, body, meta) {
      putCalls.push({ key: key, body: body, meta: meta });
    },
  };
  var db = {
    runSql: function (sql, args) {
      if (/INSERT INTO/.test(sql)) {
        insertedRow = {
          journal_id: args[0], direction: args[1], actor_id: args[2],
          message_id: args[3], archived_at: args[4], size_bytes: args[5],
          regimes: args[6], floor_until: args[7], legal_hold: 0,
          storage_key: args[8], sealed_payload: args[9],
        };
        return [];
      }
      if (/SELECT.*FROM.*WHERE journal_id = \?/.test(sql)) {
        return insertedRow ? [insertedRow] : [];
      }
      return [];
    },
  };
  var j = b.mail.journal.create({
    storage: storage, vault: fakeVault,
    legalHold: { isOnHold: function () { return false; } },
    db: db, regimes: ["hipaa"], namespace: "rt",
  });
  return j.record({
    direction: "inbound", actorId: "ops", messageId: "<x@y.com>",
    headers: { from: "a@b.com", subject: "hi" },
    envelope: { mailFrom: "a@b.com", rcptTo: ["c@d.com"] },
    bodyBytes: Buffer.from("hello world", "utf8"),
  }).then(function (rv) {
    check("record() returned a journalId", typeof rv.journalId === "string" && rv.journalId.length > 0);
    check("storage.putObject called with vault-sealed string",
      putCalls.length === 1 && typeof putCalls[0].body === "string" &&
      putCalls[0].body.indexOf("vault:") === 0);
    check("DB insert carries sealed_payload",
      insertedRow && typeof insertedRow.sealed_payload === "string");
    return j.getById(rv.journalId);
  }).then(function (read) {
    check("getById returns the journal entry",
      read && read.journalId.length > 0);
    check("getById round-trips headers through vault.unseal",
      read.headers && read.headers.from === "a@b.com");
    check("getById round-trips body through vault.unseal + base64",
      read.bodyBytes.toString("utf8") === "hello world");
    check("getById round-trips envelope",
      read.envelope && read.envelope.mailFrom === "a@b.com");
  });
}

async function run() {
  testSurface();
  testBadInput();
  testRegimeFloorMath();
  testCreatesIndexTable();
  testIndexNamesValidSql();
  await testSealUnsealRoundTrip();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve(run()).then(
    function () { console.log("[mail-journal] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
  );
}
