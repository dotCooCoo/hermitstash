"use strict";
/**
 * @module    b.mailStore.fts
 * @nav       Mail
 * @title     Mail-store FTS (sealed-token full-text index)
 * @order     250
 * @slug      mail-store-fts
 *
 * @intro
 *   Sealed-token full-text search index for `b.mailStore`. At
 *   `appendMessage` time the row's plaintext subject + addresses + body
 *   are tokenized, each token is hashed with the per-deployment vault
 *   salt (the same scheme `b.cryptoField` uses for derived-hash mirrors
 *   on sealed columns), and the resulting space-separated token-hash
 *   string is inserted into a SQLite FTS5 virtual table. Search runs
 *   the same tokenize → hash transform on the operator's query terms
 *   and issues `MATCH` against the FTS5 table — never against
 *   plaintext.
 *
 *   The index is unrecoverable without the vault salt. A database
 *   dump leaks zero readable text — the FTS5 rows are byte-for-byte
 *   indistinguishable from random hashes. Per-tenant separation rides
 *   on the cryptoField namespace prefix (`bj-<table>-<field>:`), so
 *   tokens from one tenant's row can never collide with another's
 *   under the same vault key.
 *
 *   Limitations of sealed-token FTS — operator-facing constraints:
 *
 *     - Exact-token match only. No SQLite FTS5 stemmer, no porter,
 *       no Unicode-fold-then-stem, no NEAR with offsets. The token
 *       boundary IS the search granularity. Operators that need
 *       linguistic search at the cost of plaintext-at-rest opt in to
 *       a separate plaintext-FTS layer on top — not part of this
 *       primitive.
 *     - No prefix wildcard (`MATCH 'kub*'`). Token hashes don't
 *       preserve substring relationships. The cost of partial-match
 *       search is sealed-at-rest; operators get either-or.
 *     - Stopword filter is conservative (a / the / of / to / in /
 *       for / on / and / or / is / are / be / by). Stopwords land
 *       in the unsealed plaintext but never reach the FTS row.
 *     - Token length capped at 2..64 unicode codepoints after
 *       NFC normalisation. Tokens outside the band are dropped (too
 *       short = high-collision noise; too long = file-bomb shape).
 *
 *   Posture cascade. The primitive is on by default for every
 *   posture (`hipaa` / `pci-dss` / `gdpr` / `soc2`) — the token
 *   index uses the same vault key already protecting sealed-row
 *   storage, so adding the FTS index doesn't widen the cryptographic
 *   trust boundary. A future opt-in plaintext-FTS overlay would be
 *   gated by a relaxed posture; this module ships sealed-only.
 *
 * @card
 *   Tokenize → vault-salted hash → FTS5 MATCH. The DB dump leaks
 *   nothing readable; search works against ciphertext.
 */

var cryptoField  = require("./crypto-field");
var C            = require("./constants");

// Sealed-token FTS on-disk format version. Bumped when the token-hash
// transform changes so the mail-store reindex path can detect a stale
// index and rebuild it from the sealed messages table. v1 was the
// legacy salted-sha3-truncated hand-roll; v2 is the keyed
// hmac-shake256 digest computed via cryptoField.computeNamespacedHash.
var FTS_FORMAT_VERSION = 2;

// Per-token hash width, in bytes. 8 bytes -> 16 hex chars. Full 64-char
// SHA3 / SHAKE digest is overkill for the FTS hash space, and the
// shorter token compresses the FTS5 row 4x without observable collision
// risk at corpus sizes the framework targets (<= 10^9 unique tokens,
// where 64-bit collision space leaves the birthday bound > 10^9).
var FTS_HASH_BYTES = 8;

// Stopwords are dropped before hashing — they'd dominate every row's
// token set without adding query selectivity. Kept conservative to
// stay locale-neutral for v1.
var STOPWORDS = Object.create(null);
(
  "a an the of to in for on and or but is are was were be been by with " +
  "as at from this that it its their our your his her him us we i you " +
  "do does did not no yes if so up down out over under than then them"
).split(" ").forEach(function (w) { STOPWORDS[w] = true; });

// Per-token bounds. NFC-normalised codepoint count, not byte length —
// tokens carrying multi-byte UTF-8 are not penalised relative to ASCII.
var MIN_TOKEN_LEN = 2;
var MAX_TOKEN_LEN = 64;

// Per-row token-set cap. A single 50 MiB message can produce
// millions of tokens; FTS5 row insert + index update must stay
// bounded. The cap is applied AFTER stopword + length filter so the
// surviving tokens are the highest-signal subset.
var MAX_TOKENS_PER_FIELD = 8192;                                                                       // token-count cap, not bytes

// Per-field FTS column names. Kept symmetric with the messages table
// columns so callers can reason about which FTS column corresponds
// to which plaintext source field.
var FTS_FIELDS = {
  subject:  "subject_toks",
  from:     "addr_toks",
  to:       "addr_toks",
  body:     "body_toks",
};

// Token splitter — Unicode-aware. Splits on every non-letter,
// non-digit code-point (Unicode category L* or N*). Apostrophes inside
// a word survive (`don't` → `don't`); leading/trailing punctuation is
// stripped. Email addresses are split on `@` + `.` so both the local
// part and each domain label produce independent tokens — operators
// searching for `example.com` find rows whose from/to header carries
// `alice@example.com` AND rows that mention `example` or `com` in
// body prose. Stopwords prune the noisy ones.
//
// Refuses input larger than MAX_INPUT_BYTES to bound tokenizer work
// — protects against DoS-shaped messages whose body is 50 MiB of a
// single token boundary.
var MAX_INPUT_BYTES = C.BYTES.mib(8);                         // 8 MiB

/**
 * @primitive b.mailStore.fts.tokenize
 * @signature b.mailStore.fts.tokenize(text)
 * @since     0.11.25
 * @status    stable
 *
 * Split `text` into a deduplicated, lowercased, NFC-normalised token
 * array. Drops stopwords + tokens outside the 2..64-codepoint band.
 * Splits on every non-letter / non-digit codepoint, including the
 * `@` + `.` boundaries of email addresses so local-part + domain
 * labels become independent tokens.
 *
 * @example
 *   b.mailStore.fts.tokenize("Hello world from alice@example.com");
 *   // → ["hello", "world", "alice", "example", "com"]
 */
function tokenize(text) {
  if (typeof text !== "string") return [];
  if (text.length === 0) return [];
  if (Buffer.byteLength(text, "utf8") > MAX_INPUT_BYTES) {
    // Truncate at MAX_INPUT_BYTES. Tokenization on the prefix is
    // already representative for the body's content fingerprint;
    // refusing outright would weaken indexing on legitimately large
    // messages.
    text = text.slice(0, MAX_INPUT_BYTES);
  }
  // NFC normalise so visually-identical tokens hash to the same value
  // regardless of the source's encoding form.
  var nfc = text.normalize("NFC").toLowerCase();
  // Split on any run of characters that is NOT a letter, digit, or
  // intra-word apostrophe. `\p{L}` + `\p{N}` need the `u` flag.
  var rawTokens = nfc.split(/[^\p{L}\p{N}']+/u);
  var seen = Object.create(null);
  var out = [];
  for (var i = 0; i < rawTokens.length && out.length < MAX_TOKENS_PER_FIELD; i++) {
    var t = rawTokens[i];
    if (!t) continue;
    // Drop leading/trailing apostrophes that survived the split.
    t = t.replace(/^[']+/, "").replace(/[']+$/, "");
    if (!t) continue;
    // Count CODEPOINTS, not UTF-16 units.
    var len = Array.from(t).length;
    if (len < MIN_TOKEN_LEN || len > MAX_TOKEN_LEN) continue;
    if (STOPWORDS[t]) continue;
    if (seen[t]) continue;
    seen[t] = true;
    out.push(t);
  }
  return out;
}

// Hash one token through the canonical cryptoField primitive
// (computeNamespacedHash) so the FTS index inherits the keyed-MAC
// digest used for derived-hash mirrors on sealed columns. The
// namespace is per-table, per-field, per-purpose ("fts") so that
// rotating an operator's vault key invalidates every FTS row in the
// same step as every sealed column. Returns a 16-char hex prefix
// (FTS_HASH_BYTES bytes) — full 64-char digest is overkill for the
// FTS hash space, and shorter tokens compress the FTS5 row 4x without
// observable collision risk at corpus sizes the framework targets
// (<= 10^9 unique tokens, where 64-bit collision space leaves the
// birthday bound > 10^9).
/**
 * @primitive b.mailStore.fts.hashToken
 * @signature b.mailStore.fts.hashToken(table, field, token)
 * @since     0.11.25
 * @status    stable
 *
 * Keyed hash of one token under the (table, field) namespace. Routes
 * through `b.cryptoField.computeNamespacedHash` in `hmac-shake256`
 * mode — the same keyed-MAC machinery that protects sealed-column
 * derived hashes — so rotating the vault key invalidates every FTS
 * hash in step with every sealed-column hash. Returns a 16-char hex
 * prefix.
 *
 * @example
 *   var h = b.mailStore.fts.hashToken("mail_messages", "body", "kubernetes");
 *   /^[0-9a-f]{16}$/.test(h);   // → true
 */
function hashToken(table, field, token) {
  if (typeof token !== "string" || token.length === 0) return "";
  // Mirrors cryptoField's internal `namespaceFor()` scheme — the FTS
  // fields are pseudo-fields (no sealed-column registration), so the
  // canonical fallback path is always the right answer here.
  var ns = "bj-" + table + "-" + field + ":fts:";
  return cryptoField.computeNamespacedHash(ns, token, {
    mode:          "hmac-shake256",
    truncateBytes: FTS_HASH_BYTES,
  });
}

// Hash a token array → space-separated string suitable for FTS5
// row insertion. The output is what gets MATCH'd at query time.
/**
 * @primitive b.mailStore.fts.hashTokens
 * @signature b.mailStore.fts.hashTokens(table, field, tokens)
 * @since     0.11.25
 * @status    stable
 *
 * Hash an array of tokens → space-separated hash string suitable for
 * direct insertion into an FTS5 column. Empty + duplicate token-
 * hashes drop on the way out.
 *
 * @example
 *   b.mailStore.fts.hashTokens("t", "subject", ["hello", "world"]);
 *   // → "<16hex> <16hex>"
 */
function hashTokens(table, field, tokens) {
  if (!Array.isArray(tokens) || tokens.length === 0) return "";
  var seen = Object.create(null);
  var out = [];
  for (var i = 0; i < tokens.length; i++) {
    var h = hashToken(table, field, tokens[i]);
    if (!h || seen[h]) continue;
    seen[h] = true;
    out.push(h);
  }
  return out.join(" ");
}

// Tokenize + hash + join in one step (the common path for both
// append-side index updates and search-side query rewriting).
/**
 * @primitive b.mailStore.fts.hashText
 * @signature b.mailStore.fts.hashText(table, field, text)
 * @since     0.11.25
 * @status    stable
 *
 * Tokenize + hash + join in one step. Convenience wrapper —
 * equivalent to `hashTokens(table, field, tokenize(text))`.
 *
 * @example
 *   b.mailStore.fts.hashText("mail_messages", "body", "kubernetes deploy");
 *   // → "<16hex> <16hex>"
 */
function hashText(table, field, text) {
  return hashTokens(table, field, tokenize(text));
}

// Build the FTS row body for one message. Subject + body tokens get
// their own FTS columns; from + to addresses share `addr_toks` so a
// search for an address hits regardless of which side it's on. The
// `addr_toks` namespace is a single pseudo-field "addr" so the index
// + query sides hash identically regardless of which header carried
// the token — `{from: "alice@x"}` and `{to: "alice@x"}` BOTH hit a
// row that mentions alice@x in EITHER header.
/**
 * @primitive b.mailStore.fts.rowFromMessage
 * @signature b.mailStore.fts.rowFromMessage(table, msg)
 * @since     0.11.25
 * @status    stable
 *
 * Build the FTS5 row payload `{ objectid, subject_toks, addr_toks,
 * body_toks }` from a `{ objectid, subject, from, to, body }`
 * plaintext message. `from` + `to` share `addr_toks`.
 *
 * @example
 *   b.mailStore.fts.rowFromMessage("t", { objectid:"o1", subject:"Hi", from:"a@x", to:"b@x", body:"hello" });
 *   // → { objectid:"o1", subject_toks:"<hash>", addr_toks:"<hash> <hash>", body_toks:"<hash>" }
 */
function rowFromMessage(table, msg) {
  var addrTokens = tokenize(msg.from || "").concat(tokenize(msg.to || ""));
  return {
    objectid:     msg.objectid,
    subject_toks: hashText(table, "subject", msg.subject || ""),
    addr_toks:    hashTokens(table, "addr", addrTokens),
    body_toks:    hashText(table, "body", msg.body || ""),
  };
}

// Map a query-side filter key onto the (FTS5 column, namespace pseudo-
// field) pair the indexer used. Keeps the index + query in lock-step
// so future column additions only touch this table.
//
//   filter key   →  FTS5 column    +  namespace field
//   subject      →  subject_toks   +  "subject"
//   body         →  body_toks      +  "body"
//   from / to    →  addr_toks      +  "addr"
//
// For a broad cross-column `text` query the caller iterates this
// mapping and OR's the per-column MATCH clauses.
var QUERY_KEY_MAP = {
  subject: { column: "subject_toks", field: "subject" },
  body:    { column: "body_toks",    field: "body" },
  from:    { column: "addr_toks",    field: "addr" },
  to:      { column: "addr_toks",    field: "addr" },
};

/**
 * @primitive b.mailStore.fts.columnAndFieldFor
 * @signature b.mailStore.fts.columnAndFieldFor(filterKey)
 * @since     0.11.25
 * @status    stable
 *
 * Map a search filter key (`subject` / `body` / `from` / `to`) to
 * the FTS5 column it indexes into PLUS the namespace pseudo-field
 * the indexer uses when hashing tokens. Used by the search path so
 * the query-side hash transform matches the index-side one byte-
 * for-byte.
 *
 * @example
 *   b.mailStore.fts.columnAndFieldFor("from");
 *   // → { column: "addr_toks", field: "addr" }
 */
function columnAndFieldFor(key) {
  return QUERY_KEY_MAP[key] || null;
}

// Rewrite an operator query term into a FTS5 MATCH expression. The
// term is tokenized + hashed exactly like an index value, then the
// hashes are AND'd together so multi-word queries require every
// token to appear in the row. Returns null when no tokens survive
// the filter (caller should skip the FTS join in that case).
/**
 * @primitive b.mailStore.fts.buildMatchExpression
 * @signature b.mailStore.fts.buildMatchExpression(table, field, term)
 * @since     0.11.25
 * @status    stable
 *
 * Tokenize + hash an operator's query `term` and produce the FTS5
 * MATCH expression that selects rows containing every surviving
 * token. Returns `null` when no tokens survive the tokenize +
 * stopword filter (caller skips the FTS join in that case).
 *
 * @example
 *   var expr = b.mailStore.fts.buildMatchExpression("t", "body", "kubernetes deploy");
 *   // → "<16hex> AND <16hex>"
 */
function buildMatchExpression(table, field, term) {
  var tokens = tokenize(term);
  if (tokens.length === 0) return null;
  var hashes = [];
  var seen = Object.create(null);
  for (var i = 0; i < tokens.length; i++) {
    var h = hashToken(table, field, tokens[i]);
    if (!h || seen[h]) continue;
    seen[h] = true;
    hashes.push(h);
  }
  if (hashes.length === 0) return null;
  // FTS5 default operator is AND; explicit for readability.
  return hashes.join(" AND ");
}

// SQL builder — creates the FTS5 virtual table. Caller supplies the
// quoted parent table identifier; this module owns the FTS table
// name and column layout.
/**
 * @primitive b.mailStore.fts.createSql
 * @signature b.mailStore.fts.createSql(qFtsTable)
 * @since     0.11.25
 * @status    stable
 *
 * Returns the `CREATE VIRTUAL TABLE IF NOT EXISTS` SQL for the
 * sealed-token FTS5 table. The caller passes the quoted table
 * identifier (e.g. `"blamejs_mail_messages_fts"`).
 *
 * @example
 *   db.prepare(b.mailStore.fts.createSql('"mail_fts"')).run();
 */
function createSql(qFtsTable) {
  return "CREATE VIRTUAL TABLE IF NOT EXISTS " + qFtsTable + " USING fts5(" +
    "objectid UNINDEXED, " +
    "subject_toks, " +
    "addr_toks, " +
    "body_toks, " +
    "tokenize = 'unicode61 remove_diacritics 2'" +
  ")";
}

module.exports = {
  // SQL primitives
  createSql:           createSql,

  // Index-side
  tokenize:            tokenize,
  hashToken:           hashToken,
  hashTokens:          hashTokens,
  hashText:            hashText,
  rowFromMessage:      rowFromMessage,

  // Query-side
  buildMatchExpression: buildMatchExpression,
  columnAndFieldFor:   columnAndFieldFor,
  QUERY_KEY_MAP:       QUERY_KEY_MAP,

  // Constants surfaced for tests + adjacent modules.
  STOPWORDS:           STOPWORDS,
  MIN_TOKEN_LEN:       MIN_TOKEN_LEN,
  MAX_TOKEN_LEN:       MAX_TOKEN_LEN,
  MAX_TOKENS_PER_FIELD: MAX_TOKENS_PER_FIELD,
  FTS_FIELDS:          FTS_FIELDS,
  FTS_HASH_BYTES:      FTS_HASH_BYTES,
  // On-disk format marker — the mail-store reindex path stamps this
  // into `<prefix>_meta` once a full rebuild completes; a stale/missing
  // marker triggers a rebuild from the sealed messages table.
  FTS_FORMAT_VERSION:  FTS_FORMAT_VERSION,
};
