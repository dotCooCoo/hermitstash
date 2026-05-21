"use strict";
/**
 * b.mailStore.fts — sealed-token full-text search. Tests the
 * tokenizer + vault-salted token hasher + FTS5 schema + the
 * mailStore.search method that ties the index to a modseq window.
 *
 * Tokenization is deterministic given a fixed vault salt; the test
 * boots b.vault in plaintext mode (same salt every appendMessage)
 * and asserts on the resulting FTS5 row + MATCH results.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var nodeFs  = require("node:fs");
var nodeOs  = require("node:os");
var nodePath = require("node:path");

function _msg(from, to, subject, body) {
  return [
    "From: " + from,
    "To: " + to,
    "Subject: " + subject,
    "Message-Id: <" + Math.random().toString(36).slice(2) + "@x>",
  ].join("\r\n") + "\r\n\r\n" + (body || "");
}

async function _setupStore(label) {
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailfts-" + label + "-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  var nodeSqlite = require("node:sqlite");
  var db = new nodeSqlite.DatabaseSync(nodePath.join(dataDir, "store.db"));
  return { dataDir: dataDir, db: db, prefix: "blamejs_mail" };
}

function _teardown(fx) {
  try { if (fx.db && fx.db.close) fx.db.close(); } catch (_e) {}
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  try { nodeFs.rmSync(fx.dataDir, { recursive: true, force: true }); } catch (_e) {}
}

function testSurface() {
  check("mailStore.fts surface present",
        typeof b.mailStore.fts === "object" && b.mailStore.fts !== null);
  check("fts.tokenize is fn",            typeof b.mailStore.fts.tokenize === "function");
  check("fts.hashToken is fn",           typeof b.mailStore.fts.hashToken === "function");
  check("fts.hashText is fn",            typeof b.mailStore.fts.hashText === "function");
  check("fts.rowFromMessage is fn",      typeof b.mailStore.fts.rowFromMessage === "function");
  check("fts.buildMatchExpression is fn", typeof b.mailStore.fts.buildMatchExpression === "function");
  check("fts.createSql is fn",           typeof b.mailStore.fts.createSql === "function");
  check("fts.columnAndFieldFor is fn",   typeof b.mailStore.fts.columnAndFieldFor === "function");
}

function testTokenizerBasic() {
  var toks = b.mailStore.fts.tokenize("Hello world, this is a test.");
  // 'a' and 'is' are stopwords. 'hello' / 'world' / 'this' / 'test' survive.
  check("tokenizer drops stopwords",       toks.indexOf("a") === -1 && toks.indexOf("is") === -1);
  check("tokenizer keeps content tokens",  toks.indexOf("hello") !== -1 && toks.indexOf("world") !== -1 && toks.indexOf("test") !== -1);
  check("tokenizer lowercases",            toks.indexOf("hello") !== -1);
  check("tokenizer dedupes within input",  b.mailStore.fts.tokenize("foo foo foo").length === 1);
}

function testTokenizerSplitsAddresses() {
  // Email addresses MUST split on @ + . so a from-address search
  // matches the canonical local-part + domain labels independently.
  var toks = b.mailStore.fts.tokenize("alice@example.com");
  check("address splits to local part",    toks.indexOf("alice") !== -1);
  check("address splits to domain label",  toks.indexOf("example") !== -1);
  check("address keeps tld (>= 2 chars)",  toks.indexOf("com") !== -1);
}

function testTokenizerNfcAndLength() {
  // NFC normalization + min/max length filter.
  var toks = b.mailStore.fts.tokenize("café́ a aa hello supercalifragilisticexpialidocious " +
                                     "thisisaverylongtokenoversixtyfourcodepointsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
  // café accent normalizes; aa is len 2 keeps; a (single codepoint) drops.
  check("MIN_TOKEN_LEN filter drops 'a'",  toks.indexOf("a") === -1);
  check("len 2 token 'aa' survives",       toks.indexOf("aa") !== -1);
  check("long token under 64 cp survives", toks.indexOf("supercalifragilisticexpialidocious") !== -1);
  check("long token over 64 cp drops",     !toks.some(function (t) { return t.indexOf("thisisaverylongtoken") === 0; }));
}

function testHashTokenDeterministic() {
  var h1 = b.mailStore.fts.hashToken("t1", "subject", "kubernetes");
  var h2 = b.mailStore.fts.hashToken("t1", "subject", "kubernetes");
  var hDiffField = b.mailStore.fts.hashToken("t1", "body", "kubernetes");
  var hDiffTable = b.mailStore.fts.hashToken("t2", "subject", "kubernetes");
  check("same input → same hash",          h1 === h2);
  check("different field → different hash", h1 !== hDiffField);
  check("different table → different hash", h1 !== hDiffTable);
  check("hash is 16 char hex",              /^[0-9a-f]{16}$/.test(h1));
}

function testHashEmptyAndNonString() {
  check("empty string returns empty",      b.mailStore.fts.hashText("t", "subject", "") === "");
  check("null returns empty",              b.mailStore.fts.hashText("t", "subject", null) === "");
  check("non-string returns empty",        b.mailStore.fts.hashText("t", "subject", 42) === "");
}

function testBuildMatchExpressionEmptyTerm() {
  check("empty term → null",               b.mailStore.fts.buildMatchExpression("t", "subject", "") === null);
  check("stopword-only term → null",       b.mailStore.fts.buildMatchExpression("t", "subject", "the a") === null);
}

async function testStoreSearchHappyPath() {
  var fx = await _setupStore("happy");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    store.appendMessage("INBOX", _msg("alice@example.com", "bob@example.com", "Kubernetes deploy plan",
                                       "We should deploy on kubernetes next monday."));
    store.appendMessage("INBOX", _msg("carol@example.com", "bob@example.com", "Lunch?",
                                       "Wanna grab lunch this week?"));

    var r1 = store.search("INBOX", { text: "kubernetes" });
    check("text=kubernetes hits 1 row",      r1.rows.length === 1);
    check("matchExpr surfaced for diag",     typeof r1.matchExpr === "string" && r1.matchExpr.length > 0);

    var r2 = store.search("INBOX", { text: "lunch" });
    check("text=lunch hits 1 row",           r2.rows.length === 1);

    var r3 = store.search("INBOX", { from: "alice@example.com" });
    check("from=alice hits 1 row",           r3.rows.length === 1);

    var r4 = store.search("INBOX", { to: "bob@example.com" });
    check("to=bob hits both rows (shared addr_toks)", r4.rows.length === 2);

    var r5 = store.search("INBOX", { subject: "deploy" });
    check("subject=deploy hits 1 row",       r5.rows.length === 1);

    var r6 = store.search("INBOX", { body: "monday" });
    check("body=monday hits 1 row",          r6.rows.length === 1);

    var r7 = store.search("INBOX", { text: "antidisestablishment" });
    check("no-match returns empty rows",     r7.rows.length === 0);

    // No text-side filter → fall through to bare modseq cursor path.
    var rFallback = store.search("INBOX", {});
    check("empty filter returns all rows",   rFallback.rows.length === 2);

    // Combined AND filter.
    var rCombined = store.search("INBOX", { text: "deploy", from: "alice@example.com" });
    check("combined text+from intersects",   rCombined.rows.length === 1);
  } finally { _teardown(fx); }
}

async function testStoreSearchSinceModseqCursor() {
  var fx = await _setupStore("cursor");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var a = store.appendMessage("INBOX", _msg("a@x", "b@x", "First message", "alpha body"));
    store.appendMessage("INBOX", _msg("a@x", "b@x", "Second message", "beta body"));
    var c = store.appendMessage("INBOX", _msg("a@x", "b@x", "Third message", "gamma body"));

    // Search past the first message.
    var r = store.search("INBOX", { text: "body", sinceModseq: a.modseq });
    check("sinceModseq excludes anchor",      r.rows.length === 2);
    check("nextModseq advances",              r.nextModseq === c.modseq);
  } finally { _teardown(fx); }
}

async function testHardExpungeAlsoDeletesFtsRow() {
  var fx = await _setupStore("expunge");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    var m = store.appendMessage("INBOX", _msg("a@x", "b@x", "FTS row marker", "uniquephrasetokenz"));

    var before = store.search("INBOX", { text: "uniquephrasetokenz" });
    check("FTS row hits pre-expunge",          before.rows.length === 1);

    var result = store.hardExpunge("INBOX", [m.objectid]);
    check("hardExpunge reports deleted",       result.deleted.length === 1);

    // FTS row MUST also be gone — searching for the same term
    // returns zero rows post-expunge.
    var after = store.search("INBOX", { text: "uniquephrasetokenz" });
    check("FTS row cleared by hardExpunge",    after.rows.length === 0);
  } finally { _teardown(fx); }
}

async function testFtsRowIsSealed() {
  // The FTS5 row MUST hold opaque hashes — no readable plaintext from
  // the message subject / from / to / body must appear in the FTS5
  // table. This is the sealed-at-rest invariant for the FTS index.
  var fx = await _setupStore("sealed");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    store.appendMessage("INBOX", _msg("alice@example.com", "bob@example.com",
                                       "CONFIDENTIAL Q3 financial results",
                                       "Revenue increased 42% year-over-year"));

    var ftsRow = fx.db.prepare("SELECT subject_toks, addr_toks, body_toks FROM \"" +
                                fx.prefix + "_messages_fts\" LIMIT 1").get();
    check("FTS row exists",                    !!ftsRow);
    // None of the plaintext tokens leak.
    var combined = ftsRow.subject_toks + " " + ftsRow.addr_toks + " " + ftsRow.body_toks;
    check("no 'confidential' plaintext leak",  combined.toLowerCase().indexOf("confidential") === -1);
    check("no 'revenue' plaintext leak",       combined.toLowerCase().indexOf("revenue") === -1);
    check("no 'alice' plaintext leak",         combined.toLowerCase().indexOf("alice") === -1);
    check("no '@' character (no addresses)",   combined.indexOf("@") === -1);
    // Each token is a 16-char hex string separated by spaces.
    check("subject_toks shape is hash-only",   /^([0-9a-f]{16}( [0-9a-f]{16})*)?$/.test(ftsRow.subject_toks));
    check("body_toks shape is hash-only",      /^([0-9a-f]{16}( [0-9a-f]{16})*)?$/.test(ftsRow.body_toks));
    check("addr_toks shape is hash-only",      /^([0-9a-f]{16}( [0-9a-f]{16})*)?$/.test(ftsRow.addr_toks));
  } finally { _teardown(fx); }
}

async function testSearchRespectsLimitCap() {
  var fx = await _setupStore("limit");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    for (var i = 0; i < 12; i += 1) {
      store.appendMessage("INBOX", _msg("a@x", "b@x", "Message " + i, "shared body token"));
    }
    var r = store.search("INBOX", { text: "shared", limit: 5 });
    check("explicit limit honoured",           r.rows.length === 5);

    // Default limit (100) caps result count.
    var rDefault = store.search("INBOX", { text: "shared" });
    check("default limit returns up to 12",    rDefault.rows.length === 12);
  } finally { _teardown(fx); }
}

async function testQueryKeyMapping() {
  check("subject maps to subject_toks/subject",
        b.mailStore.fts.columnAndFieldFor("subject").column === "subject_toks" &&
        b.mailStore.fts.columnAndFieldFor("subject").field  === "subject");
  check("body maps to body_toks/body",
        b.mailStore.fts.columnAndFieldFor("body").column === "body_toks" &&
        b.mailStore.fts.columnAndFieldFor("body").field  === "body");
  check("from maps to addr_toks/addr",
        b.mailStore.fts.columnAndFieldFor("from").column === "addr_toks" &&
        b.mailStore.fts.columnAndFieldFor("from").field  === "addr");
  check("to maps to addr_toks/addr (shared)",
        b.mailStore.fts.columnAndFieldFor("to").column === "addr_toks" &&
        b.mailStore.fts.columnAndFieldFor("to").field  === "addr");
  check("unknown key returns null",
        b.mailStore.fts.columnAndFieldFor("unknown") === null);
}

async function run() {
  // One-time vault init for the sync tokenizer + hash tests — the
  // hash routine reads vault.getDerivedHashSalt() so the salt MUST
  // exist before any hashToken call runs. The per-test fixtures
  // reset + re-init the vault for the async store-level tests.
  var bootDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "mailfts-boot-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  b.cryptoField.clearForTest();
  await b.vault.init({ dataDir: bootDir, mode: "plaintext" });

  testSurface();
  testTokenizerBasic();
  testTokenizerSplitsAddresses();
  testTokenizerNfcAndLength();
  testHashTokenDeterministic();
  testHashEmptyAndNonString();
  testBuildMatchExpressionEmptyTerm();
  await testStoreSearchHappyPath();
  await testStoreSearchSinceModseqCursor();
  await testHardExpungeAlsoDeletesFtsRow();
  await testFtsRowIsSealed();
  await testSearchRespectsLimitCap();
  await testQueryKeyMapping();

  try { nodeFs.rmSync(bootDir, { recursive: true, force: true }); } catch (_e) {}

  console.log("[mail-store-fts] OK — " + (require("../helpers/check").getChecks()) + " checks passed");
}

if (require.main === module) {
  run().catch(function (e) {
    console.error("[mail-store-fts] FAIL:", e);
    process.exit(1);
  });
}

module.exports = { run: run };
