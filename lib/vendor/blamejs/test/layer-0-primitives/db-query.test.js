// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * db-query — canonical test file for lib/db-query.js (the chainable Query
 * builder behind b.db.from()).
 *
 * Two harnesses, matching the existing db-query sub-concern files:
 *   - a SQL-recording fake handle (mirrors db-query-cross-schema.test.js's
 *     _fakeDb) for the constructor / column-gate / dialect / WhereBuilder /
 *     JSONB-guard / whereRaw branches that throw or emit before a row is
 *     touched — no db bootstrap needed (sealRow/unsealRow no-op on an
 *     unregistered table, exactly as the cross-schema sibling relies on);
 *   - the in-process node:sqlite handle via setupTestDb for the real
 *     execution paths: sealed-field query rewrite, residency write-gate,
 *     per-row-key writes, streaming, and the raw-write residency helpers.
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var dbQuery        = require("../../lib/db-query");
var Query          = dbQuery.Query;

// SQL-recording fake handle. `prepare(sql)` records the statement and
// returns a stmt stub whose result rows are configurable per test (get /
// all / iterate / run.changes). Rolling this mirrors the sibling
// db-query-cross-schema.test.js `_fakeDb` — no shared helper provides a
// stmt-recording db handle.
function _recordingDb(opts) {
  opts = opts || {};
  var prepared = [];
  return {
    prepared: prepared,
    dialect:  opts.dialect,
    prepare:  function (sql) {
      prepared.push(sql);
      return {
        get: function () { return opts.getResult !== undefined ? opts.getResult : null; },
        all: function () { return opts.allResult !== undefined ? opts.allResult : []; },
        run: function () { return { changes: opts.changes !== undefined ? opts.changes : 0 }; },
        iterate: function () {
          if (opts.iterateThrows) throw new Error("iterate boom");
          if (opts.nextThrows) return { next: function () { throw new Error("next boom"); } };
          return { next: function () { return { done: true }; } };
        },
      };
    },
  };
}

function _codeOf(fn) {
  try { fn(); } catch (e) { return (e && e.code) || (e && e.message) || "threw"; }
  return null;
}
function _threw(fn) { return _codeOf(fn) !== null; }

// ---------------------------------------------------------------------------
// Fake-handle group — validation / SQL-shape branches (no db bootstrap).
// ---------------------------------------------------------------------------

async function testConstructorValidation() {
  var db = _recordingDb();
  check("non-string tableName → TypeError",
        _threw(function () { new Query(db, 123); }));
  check("three-part identifier rejected",
        /exactly 'schema.table'/.test(_codeOf(function () { new Query(db, "a.b.c"); })));
  check("empty schema part rejected",
        _threw(function () { new Query(db, ".t"); }));
  check("empty table part rejected",
        _threw(function () { new Query(db, "s."); }));
  check("invalid schema identifier rejected",
        _threw(function () { new Query(db, "DROP TABLE.users"); }));
  check("invalid table identifier rejected",
        _threw(function () { new Query(db, "audit.DROP TABLE"); }));

  // primaryKey construction opt: valid identifier accepted, invalid rejected.
  var withPk = new Query(db, "t", { primaryKey: "pk" });
  check("primaryKey opt sets the pk column", withPk._pkColumn() === "pk");
  check("invalid primaryKey identifier rejected",
        _threw(function () { new Query(db, "t", { primaryKey: "bad name" }); }));
  var noPk = new Query(db, "t");
  check("default pk column is _id when no primaryKey opt", noPk._pkColumn() === "_id");

  // declaredColumns accepts both an array and a Set.
  var fromArr = new Query(db, "t", { declaredColumns: ["a", "b"] });
  check("declaredColumns array is normalized to a Set", fromArr._declaredColumns instanceof Set);
  var fromSet = new Query(db, "t", { declaredColumns: new Set(["a"]) });
  check("declaredColumns Set is used as-is", fromSet._declaredColumns.has("a"));
}

async function testColumnGate() {
  var db = _recordingDb();
  var declared = { declaredColumns: ["a", "b"] };

  // reject (default) — unknown column throws before any SQL is built.
  check("reject mode: unknown column refused",
        /not a declared column/.test(
          _codeOf(function () { new Query(db, "t", declared).where({ c: 1 }); })));
  // declared column passes.
  check("reject mode: declared column passes",
        !_threw(function () { new Query(db, "t", declared).where({ a: 1 }); }));

  // warn mode — unknown column is allowed (audit drop-silent), no throw.
  check("warn mode: unknown column allowed (audit-only)",
        !_threw(function () {
          new Query(db, "t", { declaredColumns: ["a"], columnGateMode: "warn" }).where({ z: 9 });
        }));
  // off mode — gate skipped entirely.
  check("off mode: unknown column allowed",
        !_threw(function () {
          new Query(db, "t", { declaredColumns: ["a"], columnGateMode: "off" }).where({ z: 9 });
        }));
  // no declaredColumns — gate disabled.
  check("no declaredColumns: gate disabled",
        !_threw(function () { new Query(db, "t").where({ anything: 1 }); }));

  // allowedColumns() — always enforced, tighter than the schema set.
  check("allowedColumns() refuses a column outside the explicit set",
        /allowedColumns\(\) set/.test(
          _codeOf(function () {
            new Query(db, "t", declared).allowedColumns(["a"]).where({ b: 1 });
          })));
  check("allowedColumns() allows a column inside the explicit set",
        !_threw(function () {
          new Query(db, "t", declared).allowedColumns(["a"]).where({ a: 1 });
        }));
  check("allowedColumns([]) → TypeError (non-empty array required)",
        _threw(function () { new Query(db, "t").allowedColumns([]); }));
  check("allowedColumns(non-array) → TypeError",
        _threw(function () { new Query(db, "t").allowedColumns("a"); }));
  check("allowedColumns([bad identifier]) rejected",
        _threw(function () { new Query(db, "t").allowedColumns(["bad name"]); }));

  // select() / orderBy() also run the gate.
  check("select() refuses an undeclared column",
        /not a declared column/.test(
          _codeOf(function () { new Query(db, "t", declared).select(["nope"]); })));
  check("orderBy() refuses an undeclared column",
        /not a declared column/.test(
          _codeOf(function () { new Query(db, "t", declared).orderBy("nope"); })));
}

async function testDialectAndSingleRowWrite() {
  // Dialect resolution: postgres / mysql / unknown-fallback / undefined.
  var pg = _recordingDb({ dialect: "postgres", getResult: { _id: "x" } });
  new Query(pg, "t").where({ a: 1 }).first();
  check("postgres handle drives a SELECT", pg.prepared.some(function (s) { return /SELECT/.test(s); }));

  var weird = _recordingDb({ dialect: "wat" });
  new Query(weird, "t").where({ a: 1 }).first();
  check("unknown dialect falls back to sqlite quoting",
        weird.prepared.some(function (s) { return /FROM "t"/.test(s); }));

  // MySQL single-row UPDATE: no self-referential subquery — resolve the PK
  // in a prior SELECT then write WHERE pk = ?. getResult supplies the PK.
  var my = _recordingDb({ dialect: "mysql", getResult: { pk: "row-7" }, changes: 1 });
  var updated = new Query(my, "t", { primaryKey: "pk" }).where({ a: 1 }).updateOne({ name: "y" });
  check("mysql single-row update returns true when a row matched", updated === true);
  check("mysql update emits backtick-quoted UPDATE",
        my.prepared.some(function (s) { return /UPDATE `t` SET/.test(s); }));
  check("mysql update resolves the PK in a prior SELECT",
        my.prepared.some(function (s) { return /SELECT `pk` FROM `t`/.test(s); }));

  // MySQL single-row update with NO matching row → _resolveSinglePk null → 0.
  var myNone = _recordingDb({ dialect: "mysql", getResult: null });
  check("mysql single-row update returns false when no row matched",
        new Query(myNone, "t").where({ a: 1 }).updateOne({ name: "y" }) === false);

  // MySQL: a matched row whose PK value is NULL still resolves to "no row".
  var myNullPk = _recordingDb({ dialect: "mysql", getResult: { pk: null } });
  check("mysql single-row update treats a NULL pk value as no match",
        new Query(myNullPk, "t", { primaryKey: "pk" }).where({ a: 1 }).updateOne({ name: "y" }) === false);

  // Postgres single-row update uses the PK sub-select idiom (not the sqlite
  // rowid), exercising the non-sqlite row-locator column.
  var pgUpd = _recordingDb({ dialect: "postgres", getResult: { _id: "x" }, changes: 1 });
  check("postgres single-row update returns true when a row matched",
        new Query(pgUpd, "t").where({ a: 1 }).updateOne({ name: "y" }) === true);
  check("postgres single-row update uses the _id sub-select",
        pgUpd.prepared.some(function (s) { return /SELECT "_id" FROM "t"/.test(s); }));

  // count() over a handle that returns no aggregate row falls back to 0.
  var noRow = _recordingDb({ getResult: null });
  check("count() returns 0 when the handle yields no row",
        new Query(noRow, "t").where({ a: 1 }).count() === 0);

  // MySQL single-row DELETE, matching + non-matching.
  var myDel = _recordingDb({ dialect: "mysql", getResult: { _id: "d1" }, changes: 1 });
  check("mysql single-row delete returns true when a row matched",
        new Query(myDel, "t").where({ a: 1 }).deleteOne() === true);
  var myDelNone = _recordingDb({ dialect: "mysql", getResult: null });
  check("mysql single-row delete returns false when no row matched",
        new Query(myDelNone, "t").where({ a: 1 }).deleteOne() === false);
}

async function testWhereOperatorAndJsonbGuards() {
  var db = _recordingDb();

  // invalid operator.
  check("invalid where operator rejected",
        /invalid where operator/.test(
          _codeOf(function () { new Query(db, "t").where("c", "NOPE", 1); })));

  // IN shape validation (non-sealed path).
  check("IN with a non-array value rejected",
        _threw(function () { new Query(db, "t").where("c", "IN", "x"); }));
  check("IN with an empty array rejected",
        _threw(function () { new Query(db, "t").where("c", "IN", []); }));

  // JSONB containment @> — object value (validate + canonical stringify).
  check("@> accepts a valid object value",
        !_threw(function () { new Query(db, "t").where("meta", "@>", { a: 1 }); }));
  // @> — pre-stringified JSON string value (parse + validate).
  check("@> accepts a valid JSON string value",
        !_threw(function () { new Query(db, "t").where("meta", "@>", '{"a":1}'); }));
  check("@> rejects an invalid JSON string value",
        /invalid JSON string/.test(
          _codeOf(function () { new Query(db, "t").where("meta", "@>", "{not json"); })));
  check("@> rejects an object with a control-char string leaf",
        _threw(function () { new Query(db, "t").where("meta", "@>", { a: "" }); }));

  // JSONB key-existence operators.
  check("? accepts a string key", !_threw(function () { new Query(db, "t").where("meta", "?", "k"); }));
  check("? rejects a non-string key",
        _threw(function () { new Query(db, "t").where("meta", "?", 123); }));
  check("?| accepts a non-empty array of keys",
        !_threw(function () { new Query(db, "t").where("meta", "?|", ["k1", "k2"]); }));
  check("?| rejects a non-array value",
        _threw(function () { new Query(db, "t").where("meta", "?|", "k"); }));
  check("?& rejects an empty array",
        _threw(function () { new Query(db, "t").where("meta", "?&", []); }));
  check("?& accepts a non-empty array of keys",
        !_threw(function () { new Query(db, "t").where("meta", "?&", ["k"]); }));

  // where() arg-shape variants + whereNull / whereNotNull recording.
  check("where(field, value) 2-arg shorthand records",
        !_threw(function () { new Query(db, "t").where("c", "v"); }));
  check("whereNull / whereNotNull record IS / IS NOT predicates",
        !_threw(function () { new Query(db, "t").whereNull("c").whereNotNull("d"); }));
}

async function testWhereRawValidation() {
  var db = _recordingDb();
  check("whereRaw with a non-string sql rejected",
        _threw(function () { new Query(db, "t").whereRaw(123); }));
  check("whereRaw with an empty sql rejected",
        _threw(function () { new Query(db, "t").whereRaw(""); }));
  check("whereRaw placeholder/param count mismatch rejected",
        /placeholder/.test(_codeOf(function () { new Query(db, "t").whereRaw("a = ?", []); })));
  check("whereRaw coerces a scalar param to a single-element array",
        !_threw(function () { new Query(db, "t").whereRaw("a = ?", 5); }));
  check("whereRaw treats null params as an empty list",
        !_threw(function () { new Query(db, "t").whereRaw("a IS NOT NULL", null); }));
  check("whereRaw refuses an embedded string literal by default",
        _threw(function () { new Query(db, "t").whereRaw("name = 'x'"); }));
  check("whereRaw allows an embedded literal under allowLiterals:true",
        !_threw(function () { new Query(db, "t").whereRaw("name = 'x'", [], { allowLiterals: true }); }));
}

async function testSelectOrderLimitOffsetValidation() {
  var db = _recordingDb();
  check("select(non-array) rejected",
        _threw(function () { new Query(db, "t").select("c"); }));
  check("orderBy invalid direction rejected",
        /asc.*desc|desc/.test(_codeOf(function () { new Query(db, "t").orderBy("c", "sideways"); })));

  // Multi-column orderBy: first call single-object shape, second promotes to
  // array, third pushes.
  var q = new Query(db, "t");
  q.orderBy("a");
  check("first orderBy keeps the single-object shape", q._orderBy && q._orderBy.field === "a");
  q.orderBy("b", "desc");
  check("second orderBy promotes to an array", Array.isArray(q._orderBy) && q._orderBy.length === 2);
  q.orderBy("c");
  check("third orderBy pushes onto the array", q._orderBy.length === 3);

  check("limit(non-integer) rejected", _threw(function () { new Query(db, "t").limit(1.5); }));
  check("limit(negative) rejected",    _threw(function () { new Query(db, "t").limit(-1); }));
  check("offset(non-integer) rejected", _threw(function () { new Query(db, "t").offset(1.5); }));
  check("offset(negative) rejected",    _threw(function () { new Query(db, "t").offset(-1); }));

  // Full SELECT clause assembly emits through b.sql.
  var db2 = _recordingDb();
  new Query(db2, "t").where({ a: 1 }).select(["a", "b"]).orderBy("a", "desc").limit(5).offset(10).all();
  check("select+orderBy+limit+offset assemble a SELECT",
        db2.prepared.some(function (s) { return /ORDER BY "a" DESC/.test(s) && /LIMIT/.test(s); }));
}

async function testWhereGroupOrWhereValidation() {
  var db = _recordingDb();
  check("whereGroup(non-function) rejected",
        _threw(function () { new Query(db, "t").whereGroup("x"); }));
  check("whereGroup(empty closure) is a no-op (chainable)",
        new Query(db, "t").whereGroup(function () {}) instanceof Query);
  check("orWhere without a prior where rejected",
        /no prior where/.test(_codeOf(function () { new Query(db, "t").orWhere({ a: 1 }); })));

  // WhereBuilder shape validation + build() back-compat shim, exercised
  // inside a whereGroup closure (the only way to reach a WhereBuilder).
  var built = null, empty = null, badField = false, badIn = false, badRawStr = false, badRawCount = false;
  new Query(db, "t").whereGroup(function (qb) {
    empty = qb.build();                              // 0 parts → { sql:"", params:[] }
    badField    = _threw(function () { qb.eq(123, "v"); });
    badIn       = _threw(function () { qb.in("a", "notarray"); });
    badRawStr   = _threw(function () { qb.raw(123); });
    badRawCount = _threw(function () { qb.raw("a = ?", []); });
    // WhereBuilder.raw param coercion + allowLiterals opt-out.
    qb.raw("m = ?", 5);                              // scalar coerced to [5]
    qb.raw("n IS NULL", null);                       // null → []
    qb.raw("p = 'lit'", [], { allowLiterals: true }); // static literal allowed
    qb.eq("a", 1).neq("b", 2).gt("c", 3).gte("d", 4).lt("e", 5).lte("f", 6)
      .in("g", [1, 2]).like("h", "x%")
      .orEq("a", 9).orNeq("b", 8).orGt("c", 7).orGte("d", 6).orLt("e", 5).orLte("f", 4)
      .orIn("g", [3]).orLike("h", "y%")
      .raw("j = ?", [1]);
    built = qb.build();                              // non-empty → fragment + params
  }).all();
  check("WhereBuilder.build() returns an empty fragment for no parts",
        empty && empty.sql === "" && empty.params.length === 0);
  check("WhereBuilder.build() returns a fragment once parts exist",
        built && built.sql.length > 0 && built.params.length > 0);
  check("WhereBuilder rejects a non-string field", badField);
  check("WhereBuilder rejects a non-array IN value", badIn);
  check("WhereBuilder.raw rejects a non-string sql", badRawStr);
  check("WhereBuilder.raw rejects a placeholder/param count mismatch", badRawCount);
}

async function testCryptoFieldKeyFallback() {
  // Schema-qualified table with no per-schema sealed registration falls back
  // to the bare table name for the sealed-field registry lookup.
  var db = _recordingDb();
  var q = new Query(db, "audit.events");
  check("schema-qualified key falls back to the bare table", q._cryptoFieldKey() === "events");
  q.where({ a: 1 }).first();
  check("schema-qualified SELECT emits the quoted two-part name",
        db.prepared.some(function (s) { return /"audit"\."events"/.test(s); }));
}

async function testIncrementBranches() {
  // increment() runs entirely on the fake handle: column/delta validation
  // (throws before any SQL), then the COALESCE emission.
  var db = _recordingDb({ changes: 1 });
  check("increment(non-string column) rejected",
        _threw(function () { new Query(db, "t").where({ a: 1 }).increment(123, 1); }));
  check("increment(non-integer delta) rejected",
        /finite integer/.test(
          _codeOf(function () { new Query(db, "t").where({ a: 1 }).increment("cnt", 1.5); })));
  check("increment without a where(...) refused",
        /unconditional/.test(_codeOf(function () { new Query(db, "t").increment("cnt", 1); })));

  var n = new Query(db, "t").where({ a: 1 }).increment("cnt", 5);
  check("increment returns rows-changed", n === 1);
  check("increment emits a COALESCE(col,0)+? expression",
        db.prepared.some(function (s) { return /COALESCE\("cnt", 0\) \+ \?/.test(s); }));

  db = _recordingDb({ changes: 1 });
  new Query(db, "t").where({ a: 1 }).increment("cnt");
  check("increment default delta is 1 (emits COALESCE)",
        db.prepared.some(function (s) { return /COALESCE/.test(s); }));
}

async function testStreamValidationOnFakeHandle() {
  // iterate() throwing during stream setup destroys the returned Readable
  // with that error rather than throwing synchronously. getStreamLimit is
  // read from the live db module, so run under an initialized db.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dbq-stream-fake-"));
  try {
    await setupTestDb(tmpDir);
    var db = _recordingDb({ iterateThrows: true });
    var err = await _streamError(new Query(db, "users").stream());
    check("stream() surfaces an iterate() failure as a stream error",
          err && /iterate boom/.test(String(err.message)));

    // A throw DURING iteration (iter.next()) is caught inside the read pump
    // and destroys the stream rather than crashing the process.
    var db2 = _recordingDb({ nextThrows: true });
    var err2 = await _streamError(new Query(db2, "users").stream());
    check("stream() catches a mid-iteration throw and errors the stream",
          err2 && /next boom/.test(String(err2.message)));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---------------------------------------------------------------------------
// Real-execution group (setupTestDb — default users schema).
// ---------------------------------------------------------------------------

async function testInsertUpdateDeleteExecution() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dbq-crud-"));
  try {
    await setupTestDb(tmpDir);

    check("insertOne(non-object) rejected",
          _threw(function () { b.db.from("users").insertOne("nope"); }));
    check("insertMany(non-array) rejected",
          _threw(function () { b.db.from("users").insertMany("nope"); }));

    // _id auto-generated when omitted.
    var made = b.db.from("users").insertOne({ email: "auto@example.com", name: "Auto" });
    check("insertOne auto-generates an _id", typeof made._id === "string" && made._id.length > 0);

    // insertMany over a loop.
    var many = b.db.from("users").insertMany([
      { _id: "m1", email: "m1@example.com", name: "M1" },
      { _id: "m2", email: "m2@example.com", name: "M2" },
    ]);
    check("insertMany returns one filled row per input", many.length === 2 && many[0]._id === "m1");

    // count(): populated + filtered-to-zero.
    check("count() reflects inserted rows", b.db.from("users").count() >= 3);
    check("count() is 0 when nothing matches",
          b.db.from("users").where({ _id: "does-not-exist" }).count() === 0);
    check("first() returns null when nothing matches",
          b.db.from("users").where({ _id: "does-not-exist" }).first() === null);

    // Unconditional update / delete are refused.
    check("unconditional update refused",
          /unconditional update/.test(_codeOf(function () { b.db.from("users").updateMany({ name: "x" }); })));
    check("unconditional delete refused",
          /unconditional delete/.test(_codeOf(function () { b.db.from("users").deleteMany(); })));

    // update requires a non-object → throw; empty change set → throw.
    check("update(non-object) rejected",
          _threw(function () { b.db.from("users").where({ _id: "m1" }).updateMany(5); }));
    check("update with an empty change set rejected",
          /empty/.test(_codeOf(function () { b.db.from("users").where({ _id: "m1" }).updateOne({}); })));

    // updateOne single-row (sqlite rowid idiom): matched + unmatched.
    check("updateOne returns true when a row matched",
          b.db.from("users").where({ _id: "m1" }).updateOne({ name: "M1b" }) === true);
    check("updateOne re-read shows the change",
          b.db.from("users").where({ _id: "m1" }).first().name === "M1b");
    check("updateOne returns false when no row matched",
          b.db.from("users").where({ _id: "ghost" }).updateOne({ name: "z" }) === false);

    // updateMany returns the changed count.
    var changed = b.db.from("users").where({ status: "active" }).updateMany({ status: "active" });
    check("updateMany returns a numeric changed count", typeof changed === "number");

    // deleteOne single-row + deleteMany.
    check("deleteOne returns true when a row matched",
          b.db.from("users").where({ _id: "m2" }).deleteOne() === true);
    check("deleteOne returns false when no row matched",
          b.db.from("users").where({ _id: "m2" }).deleteOne() === false);
    var delN = b.db.from("users").where({ _id: "m1" }).deleteMany();
    check("deleteMany returns the deleted count", delN === 1);

    // Multi-column ORDER BY reaches the array-of-entries clause path.
    check("multi-column orderBy assembles and returns rows",
          b.db.from("users").orderBy("status", "asc").orderBy("_id", "desc").all().length >= 1);

    // whereNull / whereNotNull execute (createdAt is omitted → NULL).
    check("whereNull finds rows with a NULL column",
          b.db.from("users").whereNull("createdAt").all().length >= 1);
    check("whereNotNull finds no rows when the column is always NULL",
          b.db.from("users").whereNotNull("createdAt").all().length === 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSealedFieldQuery() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dbq-sealed-"));
  try {
    await setupTestDb(tmpDir);
    b.db.from("users").insertOne({ _id: "s1", email: "alice@example.com", name: "Alice" });

    // Equality on a sealed field rewrites to the derived hash + dual-reads
    // the legacy digest (op "=" → IN of [active, legacy]).
    var eq = b.db.from("users").where("email", "=", "alice@example.com").all();
    check("sealed-field equality finds the row via the derived hash",
          eq.length === 1 && eq[0]._id === "s1");

    // Non-"=" operator on a sealed field takes the scalar-value branch.
    check("sealed-field != executes without error",
          !_threw(function () { b.db.from("users").where("email", "!=", "nobody@example.com").all(); }));

    // whereIn on a sealed field maps each element through the hash.
    var inRows = b.db.from("users").whereIn("email", ["alice@example.com"]).all();
    check("sealed-field whereIn finds matching rows",
          inRows.length === 1 && inRows[0]._id === "s1");

    // A sealed column with NO derived hash (name) cannot be queried.
    check("sealed field without a derived hash refuses equality",
          /derived hash/.test(_codeOf(function () { b.db.from("users").where("name", "=", "Alice").all(); })));
    check("sealed field without a derived hash refuses whereIn",
          /derived hash/.test(_codeOf(function () { b.db.from("users").whereIn("name", ["Alice"]).all(); })));
    // Empty IN array on a sealed field is refused too.
    check("sealed field whereIn with an empty array rejected",
          _threw(function () { b.db.from("users").whereIn("email", []).all(); }));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testStreamExecution() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dbq-stream-"));
  try {
    await setupTestDb(tmpDir);
    b.db.from("users").insertOne({ _id: "r1", email: "r1@example.com", name: "R1" });
    b.db.from("users").insertOne({ _id: "r2", email: "r2@example.com", name: "R2" });
    b.db.from("users").insertOne({ _id: "r3", email: "r3@example.com", name: "R3" });

    // Normal stream: every row auto-unsealed.
    var rows = await _collect(b.db.from("users").stream());
    check("stream() yields every row unsealed", rows.length === 3 && rows[0].email.indexOf("@") !== -1);

    // Per-call streamLimit override under the ceiling still yields all rows.
    var rowsCapped = await _collect(b.db.from("users").stream({ streamLimit: 100 }));
    check("stream() honours a per-call streamLimit override", rowsCapped.length === 3);

    // streamLimit exceeded → the Readable is destroyed with an error.
    var streamErr = null;
    try { await _collect(b.db.from("users").stream({ streamLimit: 1 })); }
    catch (e) { streamErr = e; }
    check("stream() destroys with an error past the streamLimit",
          streamErr && /exceeding streamLimit/.test(String(streamErr.message)));

    // Bad per-call streamLimit values are rejected at setup.
    check("stream({streamLimit:0}) rejected",  _threw(function () { b.db.from("users").stream({ streamLimit: 0 }); }));
    check("stream({streamLimit:-5}) rejected", _threw(function () { b.db.from("users").stream({ streamLimit: -5 }); }));
    check("stream({streamLimit:1.5}) rejected", _threw(function () { b.db.from("users").stream({ streamLimit: 1.5 }); }));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testWhereGroupOrWhereExecution() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dbq-group-"));
  try {
    await setupTestDb(tmpDir);
    b.db.from("users").insertOne({ _id: "a", email: "a@x.com", name: "A", status: "active" });
    b.db.from("users").insertOne({ _id: "p", email: "p@x.com", name: "P", status: "pending" });
    b.db.from("users").insertOne({ _id: "c", email: "c@x.com", name: "C", status: "closed" });

    // whereGroup with an AND/OR sub-expression + LIKE + IN replay paths.
    var grouped = b.db.from("users").whereGroup(function (qb) {
      qb.eq("status", "active").orEq("status", "pending").orLike("status", "clos%").orIn("_id", ["c"]);
    }).all();
    check("whereGroup replays eq/orEq/orLike/orIn", grouped.length === 3);

    // whereGroup empty closure is a no-op (returns all rows).
    check("whereGroup(empty) matches everything",
          b.db.from("users").whereGroup(function () {}).all().length === 3);

    // whereGroup with an AND LIKE + AND raw path. LIKE / raw run against the
    // stored bytes, so match on non-sealed columns (status / _id), not the
    // sealed email / name (which hold ciphertext).
    var likeAnd = b.db.from("users").where({ status: "active" }).whereGroup(function (qb) {
      qb.like("status", "act%").raw('"_id" = ?', ["a"]);
    }).all();
    check("whereGroup AND-replays like + raw", likeAnd.length === 1 && likeAnd[0]._id === "a");

    // orWhere — object map, 2-arg, 3-arg, closure, empty closure.
    check("orWhere object-map form",
          b.db.from("users").where({ status: "active" }).orWhere({ status: "pending" }).all().length === 2);
    check("orWhere 2-arg shorthand",
          b.db.from("users").where({ status: "active" }).orWhere("status", "closed").all().length === 2);
    check("orWhere 3-arg operator form",
          b.db.from("users").where({ status: "active" }).orWhere("_id", "=", "c").all().length === 2);
    check("orWhere with an IN operator OR-joins a membership predicate",
          b.db.from("users").where({ status: "active" }).orWhere("_id", "IN", ["c"]).all().length === 2);
    check("orWhere closure form",
          b.db.from("users").where({ status: "active" })
            .orWhere(function (qb) { qb.eq("status", "pending"); }).all().length === 2);
    check("orWhere empty closure restores the prior leaf",
          b.db.from("users").where({ status: "active" }).orWhere(function () {}).all().length === 1);

    // search() modes + validation. Search runs LIKE on the stored bytes, so
    // target the non-sealed `status` column (name / email hold ciphertext).
    check("search substring matches", b.db.from("users").search(["status"], "ctiv").all().length === 1);
    check("search across multiple fields OR-joins the LIKE clauses",
          b.db.from("users").search(["status", "_id"], "a").all().length >= 1);
    check("search prefix mode", b.db.from("users").search(["status"], "act", { match: "prefix" }).all().length === 1);
    check("search exact mode", b.db.from("users").search(["status"], "active", { match: "exact" }).all().length === 1);
    check("search empty term is a no-op", b.db.from("users").search(["status"], "").all().length === 3);
    check("search(non-array fields) rejected", _threw(function () { b.db.from("users").search("status", "x"); }));
    check("search(non-string term) rejected", _threw(function () { b.db.from("users").search(["status"], 5); }));
    check("search(bad match mode) rejected",
          /substring.*prefix.*exact|match/.test(
            _codeOf(function () { b.db.from("users").search(["status"], "x", { match: "fuzzy" }); })));
    check("search(undefined term) is a no-op",
          b.db.from("users").search(["status"], undefined).all().length === 3);

    // paginate — defaults + orderDir / orderDirection + opts refusals.
    var pg = b.db.from("users").where({ status: "active" }).paginate();
    check("paginate default limit/offset returns an envelope", pg.limit === 25 && pg.offset === 0);
    var pgDir = b.db.from("users").paginate({ orderBy: "status", orderDirection: "desc" });
    check("paginate honours orderDirection", pgDir.items.length === 3);
    var pgDir2 = b.db.from("users").paginate({ orderBy: "status", orderDir: "asc" });
    check("paginate honours orderDir", pgDir2.items.length === 3);
    var pgDir3 = b.db.from("users").paginate({ orderBy: "status" });
    check("paginate defaults order direction to asc", pgDir3.items.length === 3);

    // whereRaw executes end-to-end through the terminal (the recorded leaf is
    // replayed onto the b.sql builder).
    check("whereRaw executes and filters through the real terminal",
          b.db.from("users").whereRaw('"status" = ?', ["active"]).all().length === 1);
    check("paginate refuses limit=0", _threw(function () { b.db.from("users").paginate({ limit: 0 }); }));
    check("paginate refuses limit>1000", _threw(function () { b.db.from("users").paginate({ limit: 1001 }); }));
    check("paginate refuses negative offset",
          _threw(function () { b.db.from("users").paginate({ limit: 5, offset: -1 }); }));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---------------------------------------------------------------------------
// Per-row-key writes (declarePerRowKey — the insertOne / _updatePerRowKey path).
// ---------------------------------------------------------------------------

var KEYED_SCHEMA = [{
  name: "vault_rows",
  columns: { _id: "TEXT PRIMARY KEY", subjectId: "TEXT", secret: "TEXT" },
  indexes: ["subjectId"],
  sealedFields: ["secret"],
  subjectField: "subjectId",
}];

async function testPerRowKeyWrites() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dbq-prk-"));
  try {
    await setupTestDb(tmpDir, KEYED_SCHEMA);
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowKey("vault_rows", { keySize: 32 });

    // INSERT materializes a K_row and seals the sealed column under it.
    b.db.from("vault_rows").insertOne({ _id: "k1", subjectId: "subj-A", secret: "top-secret" });
    b.db.from("vault_rows").insertOne({ _id: "k2", subjectId: "subj-A", secret: "second-secret" });
    check("per-row-key insert round-trips the sealed cell",
          b.db.from("vault_rows").where({ _id: "k1" }).first().secret === "top-secret");

    // updateOne on a per-row-key table re-seals under the row's own K_row.
    var one = b.db.from("vault_rows").where({ _id: "k1" }).updateOne({ secret: "rotated" });
    check("per-row-key updateOne returns true", one === true);
    check("per-row-key updateOne re-seal round-trips",
          b.db.from("vault_rows").where({ _id: "k1" }).first().secret === "rotated");

    // updateMany on a per-row-key table walks every matched row.
    var many = b.db.from("vault_rows").where({ subjectId: "subj-A" }).updateMany({ secret: "bulk" });
    check("per-row-key updateMany re-seals every matched row", many === 2);
    check("per-row-key updateMany changed both rows",
          b.db.from("vault_rows").where({ _id: "k2" }).first().secret === "bulk");

    // Empty change set on a per-row-key update is still refused.
    check("per-row-key update with an empty change set rejected",
          /empty/.test(_codeOf(function () {
            b.db.from("vault_rows").where({ _id: "k1" }).updateMany({});
          })));
  } finally {
    try { b.cryptoField.clearResidencyForTest(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// ---------------------------------------------------------------------------
// Residency write-gate + raw-write residency helpers (dedicated db.init).
// ---------------------------------------------------------------------------

var RESIDENCY_SCHEMA = [
  { name: "residents", columns: { _id: "TEXT PRIMARY KEY", name: "TEXT", dataRegion: "TEXT" } },
  { name: "colnotes",  columns: { _id: "TEXT PRIMARY KEY", note: "TEXT" } },
  { name: "notes",     columns: { _id: "TEXT PRIMARY KEY", body: "TEXT" } },
];

async function _initResidencyDb(tmpDir) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  helpers.setTestPassphraseEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init({
    dataDir:       tmpDir,
    tmpDir:        path.join(tmpDir, "tmpfs"),
    allowNonTmpfsTmpDir: true,
    schema:        RESIDENCY_SCHEMA,
    dataResidency: { region: "eu-west-1", allowedStorageRegions: ["eu-central-1"] },
  });
}

async function _teardownResidencyDb(tmpDir) {
  try { b.compliance.clear(); } catch (_e) {}
  try { b.cryptoField.clearResidencyForTest(); } catch (_e) {}
  try { await b.audit.flush(); } catch (_e) {}
  try { b.db.close(); } catch (_e) {}
  b.audit._resetForTest();
  b.db._resetForTest();
  b.vault._resetForTest();
  b.cluster._resetForTest();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
}

async function testResidencyGates() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dbq-resid-"));
  try {
    await _initResidencyDb(tmpDir);
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowResidency("residents", {
      residencyColumn: "dataRegion",
      allowedTags:     ["eu-west-1", "us-east-1", "eu-central-1", "global"],
    });
    b.cryptoField.declareColumnResidency("colnotes", { columnResidency: { note: "us-east-1" } });

    // ----- regulated posture (GDPR) -----
    b.compliance.set("gdpr");

    check("insert missing residency tag refused",
          _codeOf(function () { b.db.from("residents").insertOne({ _id: "r0", name: "x" }); })
            === "db-query/row-residency-tag-missing");
    check("insert with a tag outside allowedTags refused",
          _codeOf(function () {
            b.db.from("residents").insertOne({ _id: "r0", name: "x", dataRegion: "zz-nope" });
          }) === "db-query/row-residency-tag-invalid");
    check("insert with a cross-border tag refused under a regulated posture",
          _codeOf(function () {
            b.db.from("residents").insertOne({ _id: "r0", name: "x", dataRegion: "us-east-1" });
          }) === "db-query/row-residency-local-mismatch");
    check("the refused cross-border row did not persist",
          b.db.from("residents").where({ _id: "r0" }).first() === null);

    // In-region + allowedStorageRegions + global all pass.
    b.db.from("residents").insertOne({ _id: "eu1", name: "in-region", dataRegion: "eu-west-1" });
    check("in-region insert persists", b.db.from("residents").where({ _id: "eu1" }).first().name === "in-region");
    b.db.from("residents").insertOne({ _id: "ec1", name: "allowed-store", dataRegion: "eu-central-1" });
    check("allowedStorageRegions tag persists",
          b.db.from("residents").where({ _id: "ec1" }).first() !== null);
    b.db.from("residents").insertOne({ _id: "gl1", name: "global-row", dataRegion: "global" });
    check("global tag bypasses the region check",
          b.db.from("residents").where({ _id: "gl1" }).first() !== null);

    // UPDATE that clears the residency column is refused; one that leaves it
    // untouched passes; one that moves it cross-border is refused.
    check("update clearing the residency tag refused",
          _codeOf(function () {
            b.db.from("residents").where({ _id: "eu1" }).updateOne({ dataRegion: null });
          }) === "db-query/row-residency-tag-missing");
    check("update not touching the residency column passes",
          b.db.from("residents").where({ _id: "eu1" }).updateOne({ name: "renamed" }) === true);
    check("update moving the row cross-border refused",
          _codeOf(function () {
            b.db.from("residents").where({ _id: "eu1" }).updateOne({ dataRegion: "us-east-1" });
          }) === "db-query/row-residency-local-mismatch");

    // Column-residency gate.
    check("column-residency mismatch refused under a regulated posture",
          _codeOf(function () { b.db.from("colnotes").insertOne({ _id: "cn1", note: "hello" }); })
            === "db-query/column-residency-mismatch");
    check("column-residency passes when the bound column is null",
          !_threw(function () { b.db.from("colnotes").insertOne({ _id: "cn0", note: null }); }));

    // ----- unregulated posture — advisory, writes pass -----
    // A runtime posture switch is forbidden; clear then re-pin.
    b.compliance.clear();
    b.compliance.set("soc2");
    check("cross-border tag passes (advisory) under an unregulated posture",
          !_threw(function () {
            b.db.from("residents").insertOne({ _id: "adv1", name: "advisory", dataRegion: "us-east-1" });
          }));
    check("advisory cross-border row DID persist",
          b.db.from("residents").where({ _id: "adv1" }).first() !== null);
    check("column-residency passes (advisory) under an unregulated posture",
          !_threw(function () { b.db.from("colnotes").insertOne({ _id: "cn2", note: "world" }); }));

    // ----- no posture pinned at all — advisory with a null posture -----
    b.compliance.clear();
    check("per-row cross-border tag is advisory when no posture is pinned",
          !_threw(function () {
            b.db.from("residents").insertOne({ _id: "np1", name: "np", dataRegion: "us-east-1" });
          }));
    check("column-residency mismatch is advisory when no posture is pinned",
          !_threw(function () { b.db.from("colnotes").insertOne({ _id: "npc", note: "x" }); }));

    // ----- raw-write residency helpers (regulated again) -----
    b.compliance.set("gdpr");

    check("_isRawWriteToresidencyTable true for a residency-table INSERT",
          dbQuery._isRawWriteToResidencyTable(
            "INSERT INTO residents (_id,name,dataRegion) VALUES ('a','b','eu-west-1')") === true);
    check("_isRawWriteToResidencyTable false for a SELECT",
          dbQuery._isRawWriteToResidencyTable("SELECT * FROM residents") === false);
    check("_isRawWriteToResidencyTable false for a non-residency table",
          dbQuery._isRawWriteToResidencyTable("INSERT INTO notes (_id,body) VALUES ('n','x')") === false);

    check("_assertRawWriteResidency returns for a non-write statement",
          _codeOf(function () { dbQuery._assertRawWriteResidency("SELECT 1"); }) === null);
    check("_assertRawWriteResidency returns for a non-residency write",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency("INSERT INTO notes (_id,body) VALUES (?,?)", ["n", "x"]);
          }) === null);

    var overLong = "INSERT INTO residents (_id,name,dataRegion) VALUES ('a','b','" +
      new Array(100002).join("x") + "')";
    check("_assertRawWriteResidency fails closed on an over-length statement",
          _codeOf(function () { dbQuery._assertRawWriteResidency(overLong); })
            === "db-query/row-residency-raw-unparseable");
    check("_assertRawWriteResidency fails closed on an unparseable body",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency("INSERT INTO residents SELECT * FROM elsewhere");
          }) === "db-query/row-residency-raw-unparseable");
    check("_assertRawWriteResidency fails closed on a column/value count mismatch",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency("INSERT INTO residents (_id, name, dataRegion) VALUES ('only-one')");
          }) === "db-query/row-residency-raw-unparseable");
    check("_assertRawWriteResidency parses a cross-border INSERT and refuses it",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "INSERT INTO residents (_id,name,dataRegion) VALUES ('a','b','us-east-1')");
          }) === "db-query/row-residency-local-mismatch");
    check("_assertRawWriteResidency binds ? params and refuses the cross-border value",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "INSERT INTO residents (_id,name,dataRegion) VALUES (?,?,?)", ["a", "b", "us-east-1"]);
          }) === "db-query/row-residency-local-mismatch");
    check("_assertRawWriteResidency parses an UPDATE and refuses the cross-border value",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency("UPDATE residents SET dataRegion='us-east-1' WHERE _id='eu1'");
          }) === "db-query/row-residency-local-mismatch");
    check("_assertRawWriteResidency fails closed on a writable-CTE residency write",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "WITH s AS (SELECT 1) INSERT INTO residents (_id,name,dataRegion) SELECT 'x','y','us-east-1'");
          }) === "db-query/row-residency-raw-unparseable");

    check("_stripLeadingSqlComments strips leading block + line comments",
          dbQuery._stripLeadingSqlComments("/* a */ -- b\n INSERT INTO x (a) VALUES (1)").indexOf("INSERT") === 0);

    // Quoted identifiers in the raw INSERT are unquoted before the gate reads
    // them; a comma inside a quoted string value is not a column separator.
    check("quoted-identifier raw INSERT is parsed and gated",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              'INSERT INTO residents ("_id","name","dataRegion") VALUES (\'a\',\'b\',\'us-east-1\')');
          }) === "db-query/row-residency-local-mismatch");
    check("a comma inside a quoted string value is not a column separator",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "INSERT INTO residents (_id,name,dataRegion) VALUES ('a,b','n','us-east-1')");
          }) === "db-query/row-residency-local-mismatch");

    // Non-string value tokens: numeric, NULL literal, and a bare expression
    // all resolve through _rawValue before the residency tag is checked.
    check("numeric + bare-expression value tokens parse; the cross-border tag still refuses",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "INSERT INTO residents (_id,name,dataRegion) VALUES (42, foo, 'us-east-1')");
          }) === "db-query/row-residency-local-mismatch");
    check("a NULL value token parses; the cross-border tag still refuses",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "INSERT INTO residents (_id,name,dataRegion) VALUES ('a', NULL, 'us-east-1')");
          }) === "db-query/row-residency-local-mismatch");

    // UPDATE with no WHERE clause — the whole SET body is the assignment list.
    check("UPDATE with no WHERE clause is parsed and gated",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency("UPDATE residents SET dataRegion='us-east-1'");
          }) === "db-query/row-residency-local-mismatch");
    // A WHERE embedded inside a quoted SET value is skipped by the quote-aware
    // scan, so the residency assignment after it is still parsed.
    check("a quoted WHERE inside a SET value does not truncate the parse",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "UPDATE residents SET name='x WHERE y', dataRegion='us-east-1' WHERE _id='eu1'");
          }) === "db-query/row-residency-local-mismatch");
    // SQL unquoted identifiers fold case: a differently-cased residency column
    // still engages the gate.
    check("a differently-cased residency column on UPDATE is still gated",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency("UPDATE residents SET DATAREGION='us-east-1' WHERE _id='eu1'");
          }) === "db-query/row-residency-local-mismatch");

    // A writable-CTE write to a NON-residency table finds no residency target.
    check("_isRawWriteToResidencyTable false for a CTE write to a non-residency table",
          dbQuery._isRawWriteToResidencyTable(
            "WITH s AS (SELECT 1) INSERT INTO notes (_id,body) SELECT 'n','x'") === false);
    // A writable-CTE UPDATE to a residency table is detected via the UPDATE
    // target token (the second alternation) and then fails closed.
    check("writable-CTE UPDATE to a residency table is detected + fails closed",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "WITH x AS (SELECT 1) UPDATE residents SET dataRegion='us-east-1' WHERE _id='eu1'");
          }) === "db-query/row-residency-raw-unparseable");

    // Doubled single-quote (SQL-escaped quote) inside a value + a
    // parenthesised value token both parse through the value splitter.
    check("a doubled '' inside a string value parses; cross-border tag refuses",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "INSERT INTO residents (_id,name,dataRegion) VALUES ('a''b','n','us-east-1')");
          }) === "db-query/row-residency-local-mismatch");
    check("a parenthesised value token parses; cross-border tag refuses",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "INSERT INTO residents (_id,name,dataRegion) VALUES ('a', substr('x',1), 'us-east-1')");
          }) === "db-query/row-residency-local-mismatch");
    // A parenthesised SET value exercises the depth tracking in the
    // before-WHERE clause splitter.
    check("a parenthesised SET value parses; cross-border tag refuses",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "UPDATE residents SET name=(1), dataRegion='us-east-1' WHERE _id='eu1'");
          }) === "db-query/row-residency-local-mismatch");
    // run(...) may pass its bound params as a single array argument; the
    // flattener unwraps it before value binding.
    check("array-wrapped bound params are flattened before binding",
          _codeOf(function () {
            dbQuery._assertRawWriteResidency(
              "INSERT INTO residents (_id,name,dataRegion) VALUES (?,?,?)", [["a", "b", "us-east-1"]]);
          }) === "db-query/row-residency-local-mismatch");

    // Integrated raw path through b.db.runSql / prepare.
    check("b.db.runSql cross-border write refused",
          _codeOf(function () {
            b.db.runSql("INSERT INTO residents (_id,name,dataRegion) VALUES ('rw1','x','us-east-1')");
          }) === "db-query/row-residency-local-mismatch");
    check("b.db.runSql cross-border row did not persist",
          b.db.from("residents").where({ _id: "rw1" }).first() === null);
    b.db.runSql("INSERT INTO residents (_id,name,dataRegion) VALUES ('rw-eu','y','eu-west-1')");
    check("in-region raw write persists (no over-rejection)",
          (b.db.from("residents").where({ _id: "rw-eu" }).first() || {}).dataRegion === "eu-west-1");
    check("b.db.prepare().run() cross-border write refused",
          _codeOf(function () {
            b.db.prepare("INSERT INTO residents (_id,name,dataRegion) VALUES (?,?,?)")
              .run("rw2", "x", "us-east-1");
          }) === "db-query/row-residency-local-mismatch");
  } finally {
    await _teardownResidencyDb(tmpDir);
  }
}

// A residency-declared table in a deployment with NO configured region: the
// region-set cross-border check is skipped (no region to compare against) but
// the allowedTags membership is still enforced.
async function testResidencyWithoutDeploymentRegion() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dbq-resid-noregion-"));
  try {
    await setupTestDb(tmpDir);               // default users schema, no dataResidency
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowResidency("users", {
      residencyColumn: "status",
      allowedTags:     ["active", "pending", "global"],
    });
    b.compliance.set("gdpr");
    check("residency tag membership is enforced with no deployment region",
          _codeOf(function () {
            b.db.from("users").insertOne({ _id: "nr1", email: "n@x.com", name: "N", status: "zz-nope" });
          }) === "db-query/row-residency-tag-invalid");
    check("an allowed tag passes when no deployment region is configured",
          !_threw(function () {
            b.db.from("users").insertOne({ _id: "nr2", email: "n2@x.com", name: "N2", status: "active" });
          }));
  } finally {
    try { b.compliance.clear(); } catch (_e) {}
    try { b.cryptoField.clearResidencyForTest(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// Collect a Readable's object-mode rows into a promise; rejects on error.
function _collect(readable) {
  return new Promise(function (resolve, reject) {
    var rows = [];
    readable.on("data", function (r) { rows.push(r); });
    readable.on("end", function () { resolve(rows); });
    readable.on("error", function (e) { reject(e); });
  });
}

// Resolve with the stream's error object (or null on clean end). The `data`
// listener puts the stream in flowing mode so the read pump actually runs —
// a throw surfaced only inside _read never fires on a paused stream.
function _streamError(readable) {
  return new Promise(function (resolve) {
    readable.on("data", function () {});
    readable.on("error", function (e) { resolve(e); });
    readable.on("end", function () { resolve(null); });
  });
}

async function run() {
  // Fake-handle validation / SQL-shape branches (no db bootstrap).
  await testConstructorValidation();
  await testColumnGate();
  await testDialectAndSingleRowWrite();
  await testWhereOperatorAndJsonbGuards();
  await testWhereRawValidation();
  await testSelectOrderLimitOffsetValidation();
  await testWhereGroupOrWhereValidation();
  await testCryptoFieldKeyFallback();
  await testIncrementBranches();
  await testStreamValidationOnFakeHandle();

  // Real-execution branches.
  await testInsertUpdateDeleteExecution();
  await testSealedFieldQuery();
  await testStreamExecution();
  await testWhereGroupOrWhereExecution();
  await testPerRowKeyWrites();
  await testResidencyGates();
  await testResidencyWithoutDeploymentRegion();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
