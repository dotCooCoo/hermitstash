// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

// ---- b.mailStore.fts.hashTokens — token-array → sealed FTS string ----
//
// hashTokens hashes each token under the (table, field) namespace and
// joins the 16-hex digests with a space — the exact string inserted into
// an FTS5 column. Empty + duplicate token-hashes drop on the way out.
// (Requires the vault salt, which run() primes before the sync tests.)
function testHashTokensBehavior() {
  var out = b.mailStore.fts.hashTokens("t", "subject", ["hello", "world"]);
  var parts = out.split(" ");
  check("hashTokens: two tokens → two space-joined hashes", parts.length === 2);
  check("hashTokens: each part is a 16-char hex hash",
    /^[0-9a-f]{16}$/.test(parts[0]) && /^[0-9a-f]{16}$/.test(parts[1]));
  // Each part equals the per-token hashToken under the same namespace.
  check("hashTokens: parts match hashToken() per token in order",
    parts[0] === b.mailStore.fts.hashToken("t", "subject", "hello") &&
    parts[1] === b.mailStore.fts.hashToken("t", "subject", "world"));

  // Duplicate tokens collapse to a single hash.
  var dup = b.mailStore.fts.hashTokens("t", "subject", ["foo", "foo", "foo"]);
  check("hashTokens: duplicate tokens collapse to one hash",
    dup === b.mailStore.fts.hashToken("t", "subject", "foo"));

  // Empty-string tokens contribute no hash and are dropped.
  var withEmpty = b.mailStore.fts.hashTokens("t", "subject", ["hello", "", "world"]);
  check("hashTokens: empty-string tokens drop (2 hashes, not 3)",
    withEmpty.split(" ").length === 2);

  // Order of first appearance is preserved.
  var ordered = b.mailStore.fts.hashTokens("t", "subject", ["bravo", "alpha"]);
  check("hashTokens: preserves first-seen token order",
    ordered.split(" ")[0] === b.mailStore.fts.hashToken("t", "subject", "bravo"));
}

function testHashTokensNamespaceScoping() {
  var base  = b.mailStore.fts.hashTokens("t1", "subject", ["kubernetes"]);
  var field = b.mailStore.fts.hashTokens("t1", "body",    ["kubernetes"]);
  var table = b.mailStore.fts.hashTokens("t2", "subject", ["kubernetes"]);
  check("hashTokens: different field → different hash", base !== field);
  check("hashTokens: different table → different hash", base !== table);
}

function testHashTokensEmptyAndNonArray() {
  check("hashTokens: empty array → empty string",
    b.mailStore.fts.hashTokens("t", "subject", []) === "");
  check("hashTokens: non-array (string) → empty string",
    b.mailStore.fts.hashTokens("t", "subject", "notanarray") === "");
  check("hashTokens: null → empty string",
    b.mailStore.fts.hashTokens("t", "subject", null) === "");
  check("hashTokens: array of only empty strings → empty string",
    b.mailStore.fts.hashTokens("t", "subject", ["", ""]) === "");
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

// Compute the legacy (v1) salted-sha3-truncated token hash exactly the
// way the pre-keyed mail-store-fts.hashToken did: sha3Hash(saltHex + ns
// + token).slice(0, 16). Used to forge an old-format FTS index so the
// reindex-on-upgrade path has a stale index to rebuild.
function _legacyHashToken(table, field, token) {
  if (typeof token !== "string" || token.length === 0) return "";
  var ns = "bj-" + table + "-" + field + ":fts:";
  var saltHex = b.vault.getDerivedHashSalt().toString("hex");
  return b.crypto.sha3Hash(saltHex + ns + token).slice(0, 16);
}

function _legacyHashTokens(table, field, tokens) {
  var seen = Object.create(null);
  var out = [];
  for (var i = 0; i < tokens.length; i += 1) {
    var h = _legacyHashToken(table, field, tokens[i]);
    if (!h || seen[h]) continue;
    seen[h] = true;
    out.push(h);
  }
  return out.join(" ");
}

// Rewrite the FTS index into the legacy (v1) format AND set the format
// marker stale, simulating an on-disk index written by a pre-keyed
// build. Reads the sealed messages table, unseals each row, retokenizes
// the plaintext, and reinserts under the legacy salted-sha3 hash.
// `markerValue` selects the stale marker: "1" (old format) or null
// (no marker row at all - pre-format-version store).
function _forgeLegacyIndex(db, prefix, table, markerValue) {
  var ftsTable = '"' + prefix + '_messages_fts"';
  var msgsTable = '"' + prefix + '_messages"';
  var metaTable = '"' + prefix + '_meta"';
  var rows = db.prepare("SELECT * FROM " + msgsTable).all();
  db.prepare("DELETE FROM " + ftsTable).run();
  var insert = db.prepare("INSERT INTO " + ftsTable +
    " (objectid, subject_toks, addr_toks, body_toks) VALUES (?, ?, ?, ?)");
  for (var i = 0; i < rows.length; i += 1) {
    var clear = b.cryptoField.unsealRow(table, rows[i]);
    var subjTokens = b.mailStore.fts.tokenize(clear.subject || "");
    var addrTokens = b.mailStore.fts.tokenize(clear.from_addr || "")
      .concat(b.mailStore.fts.tokenize(clear.to_addrs || ""));
    var bodyTokens = b.mailStore.fts.tokenize(clear.body_text || "");
    insert.run(
      clear.objectid,
      _legacyHashTokens(table, "subject", subjTokens),
      _legacyHashTokens(table, "addr", addrTokens),
      _legacyHashTokens(table, "body", bodyTokens)
    );
  }
  if (markerValue === null) {
    db.prepare("DELETE FROM " + metaTable + " WHERE key = ?").run("fts_format");
  } else {
    db.prepare("INSERT INTO " + metaTable + " (key, value) VALUES (?, ?) " +
      "ON CONFLICT(key) DO UPDATE SET value = excluded.value").run("fts_format", markerValue);
  }
}

function _readMarker(db, prefix) {
  var row = db.prepare('SELECT value FROM "' + prefix + '_meta" WHERE key = ?').get("fts_format");
  return row ? row.value : null;
}

async function testFtsReindexOnUpgrade() {
  // Forge an old-format (v1 salted-sha3) index, then construct a fresh
  // store: create() must detect the stale marker, rebuild the index
  // from the sealed messages table under the new keyed hash, find the
  // seeded docs again, and advance the marker to the current format.
  var fx = await _setupStore("reindex");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    store.appendMessage("INBOX", _msg("alice@example.com", "bob@example.com",
                                       "Kubernetes deploy plan",
                                       "We should deploy on kubernetes next monday."));
    store.appendMessage("INBOX", _msg("carol@example.com", "bob@example.com", "Lunch?",
                                       "Wanna grab lunch this week?"));

    check("fresh store stamps current marker",
          _readMarker(fx.db, fx.prefix) === String(b.mailStore.fts.FTS_FORMAT_VERSION));

    // Rewrite the index into the legacy format + stale marker.
    _forgeLegacyIndex(fx.db, fx.prefix, fx.prefix + "_messages", "1");
    check("forged marker is stale", _readMarker(fx.db, fx.prefix) === "1");

    // A new store handle against the same db triggers the reindex.
    var store2 = b.mailStore.create({ backend: fx.db });

    check("marker advanced to current after reindex",
          _readMarker(fx.db, fx.prefix) === String(b.mailStore.fts.FTS_FORMAT_VERSION));

    // Search now finds the seeded docs under the rebuilt keyed index.
    var r1 = store2.search("INBOX", { text: "kubernetes" });
    check("reindexed: text=kubernetes hits 1 row",  r1.rows.length === 1);
    check("reindexed: not flagged ftsUnavailable",  r1.ftsUnavailable !== true);
    var r2 = store2.search("INBOX", { text: "lunch" });
    check("reindexed: text=lunch hits 1 row",       r2.rows.length === 1);
    var r3 = store2.search("INBOX", { from: "alice@example.com" });
    check("reindexed: from=alice hits 1 row",       r3.rows.length === 1);

    // Idempotent - a third construction sees the current marker and does
    // not rebuild (search still works).
    var store3 = b.mailStore.create({ backend: fx.db });
    var r4 = store3.search("INBOX", { text: "kubernetes" });
    check("idempotent reindex: still 1 row",        r4.rows.length === 1);
  } finally { _teardown(fx); }
}

async function testFtsReindexRollsBackOnInterruption() {
  // Inject a failure into the reindex INSERT LOOP: the Nth FTS insert
  // throws. The whole rebuild must roll back, leaving the OLD index
  // intact + queryable and the marker NOT advanced - a retriable state,
  // never a silently half-built index.
  var fx = await _setupStore("interrupt");
  try {
    var store = b.mailStore.create({ backend: fx.db });
    store.appendMessage("INBOX", _msg("alice@example.com", "bob@example.com",
                                       "Kubernetes deploy plan",
                                       "We should deploy on kubernetes next monday."));
    store.appendMessage("INBOX", _msg("carol@example.com", "bob@example.com",
                                       "Picnic plan", "lets plan a picnic on saturday."));

    var table = fx.prefix + "_messages";
    _forgeLegacyIndex(fx.db, fx.prefix, table, "1");

    // Snapshot the forged (old-format) index so we can prove it survives
    // the rolled-back rebuild byte-for-byte.
    var ftsTable = '"' + fx.prefix + '_messages_fts"';
    var beforeRows = fx.db.prepare("SELECT objectid, subject_toks, addr_toks, body_toks FROM " +
                                   ftsTable + " ORDER BY objectid").all();
    check("forged index has 2 rows", beforeRows.length === 2);

    // A pre-rebuild MATCH against the OLD keyed scheme must hit. Compute
    // the legacy hash for "kubernetes" in the body namespace.
    var legacyKube = _legacyHashToken(table, "body", "kubernetes");
    var preHit = fx.db.prepare("SELECT objectid FROM " + ftsTable + " WHERE " +
                               ftsTable + " MATCH ?").all("body_toks:(" + legacyKube + ")");
    check("old index queryable pre-interruption", preHit.length === 1);

    // Wrap the backend so the SECOND FTS insert in the reindex loop
    // throws. Every other call delegates to the real handle - this is a
    // thin fault-injection shim around the live db, not a mock of the
    // store logic.
    var ftsInsertCalls = 0;
    var wrapped = {
      prepare: function (sql) {
        var stmt = fx.db.prepare(sql);
        if (/INSERT INTO .*_messages_fts/.test(sql)) {
          return {
            run: function () {
              ftsInsertCalls += 1;
              if (ftsInsertCalls === 2) {
                throw new Error("injected backend failure on the 2nd FTS insert");
              }
              return stmt.run.apply(stmt, arguments);
            },
            get: function () { return stmt.get.apply(stmt, arguments); },
            all: function () { return stmt.all.apply(stmt, arguments); },
          };
        }
        return stmt;
      },
    };

    var threw = false;
    try {
      b.mailStore.create({ backend: wrapped });
    } catch (e) {
      threw = true;
      check("reindex failure surfaces as MailStoreError",
            e && e.name === "MailStoreError");
    }
    check("interrupted reindex throws", threw);

    // Marker did NOT advance to the current format - it's the sentinel
    // (written before the DELETE), so a later create() retries.
    check("marker did not advance to current",
          _readMarker(fx.db, fx.prefix) !== String(b.mailStore.fts.FTS_FORMAT_VERSION));

    // The OLD index survives the rollback intact, byte-for-byte.
    var afterRows = fx.db.prepare("SELECT objectid, subject_toks, addr_toks, body_toks FROM " +
                                  ftsTable + " ORDER BY objectid").all();
    check("old index row count intact after rollback", afterRows.length === beforeRows.length);
    var identical = afterRows.length === beforeRows.length;
    for (var i = 0; i < afterRows.length && identical; i += 1) {
      identical = afterRows[i].objectid === beforeRows[i].objectid &&
                  afterRows[i].subject_toks === beforeRows[i].subject_toks &&
                  afterRows[i].addr_toks === beforeRows[i].addr_toks &&
                  afterRows[i].body_toks === beforeRows[i].body_toks;
    }
    check("old index rows unchanged after rollback", identical);

    // And the OLD index is still queryable under the legacy scheme.
    var postHit = fx.db.prepare("SELECT objectid FROM " + ftsTable + " WHERE " +
                                ftsTable + " MATCH ?").all("body_toks:(" + legacyKube + ")");
    check("old index still queryable after rollback", postHit.length === 1);

    // Retriable: a clean create() against the real backend now completes
    // the rebuild and advances the marker.
    var store2 = b.mailStore.create({ backend: fx.db });
    check("retry advances marker to current",
          _readMarker(fx.db, fx.prefix) === String(b.mailStore.fts.FTS_FORMAT_VERSION));
    var r = store2.search("INBOX", { text: "kubernetes" });
    check("retry: search finds the doc", r.rows.length === 1);
  } finally { _teardown(fx); }
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
  testHashTokensBehavior();
  testHashTokensNamespaceScoping();
  testHashTokensEmptyAndNonArray();
  testBuildMatchExpressionEmptyTerm();
  await testStoreSearchHappyPath();
  await testStoreSearchSinceModseqCursor();
  await testHardExpungeAlsoDeletesFtsRow();
  await testFtsRowIsSealed();
  await testSearchRespectsLimitCap();
  await testQueryKeyMapping();
  await testFtsReindexOnUpgrade();
  await testFtsReindexRollsBackOnInterruption();

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
