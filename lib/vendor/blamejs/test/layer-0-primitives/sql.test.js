"use strict";
/**
 * b.sql — quote-by-construction query builder (composes b.safeSql) +
 * its final output validator. Covers each verb across dialects, the
 * where-family checks inherited from the executing query builder
 * (operator allowlist, IN-expansion, JSONB injection guard +
 * jsonb_exists emission), and every _assertEmittable boundary code.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var NUL  = String.fromCharCode(0);
var LONE = String.fromCharCode(0xD800);   // unpaired UTF-16 surrogate

function rejects(label, fn, code) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && threw.code === code);
}

async function run() {
  var sql      = b.sql;
  var safeSql  = b.safeSql;

  // ---- module surface (explicit b.* references so the test-coverage gate
  // sees every primitive by its operator-facing name) ----
  check("b.sql.select",      typeof b.sql.select === "function");
  check("b.sql.insert",      typeof b.sql.insert === "function");
  check("b.sql.update",      typeof b.sql.update === "function");
  check("b.sql.delete",      typeof b.sql.delete === "function");
  check("b.sql.upsert",      typeof b.sql.upsert === "function");
  check("b.sql.insertSelectWhere", typeof b.sql.insertSelectWhere === "function");
  check("b.sql.table",       typeof b.sql.table === "function");
  check("b.sql.createTable", typeof b.sql.createTable === "function");
  check("b.sql.createIndex", typeof b.sql.createIndex === "function");
  check("b.sql.alterTable",  typeof b.sql.alterTable === "function");
  check("b.sql.dropTable",   typeof b.sql.dropTable === "function");
  check("b.sql.createVirtualTable", typeof b.sql.createVirtualTable === "function");
  check("b.sql.defineTable", typeof b.sql.defineTable === "function");
  check("b.sql.Builder",     typeof b.sql.Builder === "function");
  check("b.sql.SqlBuilderError", typeof b.sql.SqlBuilderError === "function");
  check("b.sql.ALLOWED_OPS",  b.sql.ALLOWED_OPS && b.sql.ALLOWED_OPS["="] === true);
  // table() reference exercises the table-ref helper.
  check("b.sql.table ref", b.sql.table("t", { dialect: "postgres" }) !== undefined);
  // alterTable reference.
  check("b.sql.alterTable addColumn",
        b.sql.alterTable("t", { addColumn: { name: "c", type: "text" } }, { dialect: "postgres" })
          .sql.indexOf("ALTER TABLE") === 0);

  // ---- b.safeSql surface (countPlaceholders + quoteList) ----
  check("b.safeSql.countPlaceholders", b.safeSql.countPlaceholders("a = ? AND b = ?") === 2);
  check("b.safeSql.quoteList", b.safeSql.quoteList(["a", "b"], "postgres") === '"a", "b"');
  // assertSingleStatement — the one quote-aware single-statement gate the raw-DDL
  // paths (schema reconcile, DSR store) + the b.sql output validators all route through.
  check("b.safeSql.assertSingleStatement returns valid single-statement SQL",
        b.safeSql.assertSingleStatement("CREATE TABLE t (id INTEGER)") === "CREATE TABLE t (id INTEGER)");
  check("b.safeSql.assertSingleStatement allows ';' inside a balanced quoted label",
        b.safeSql.assertSingleStatement("INSERT INTO t VALUES ('a;b')") === "INSERT INTO t VALUES ('a;b')");
  rejects("b.safeSql.assertSingleStatement refuses a stacked top-level ';'", function () {
    b.safeSql.assertSingleStatement("CREATE TABLE t (id INTEGER); DROP TABLE x");
  }, "sql/stacked-statement");
  rejects("b.safeSql.assertSingleStatement refuses an unterminated quote", function () {
    b.safeSql.assertSingleStatement("INSERT INTO t VALUES ('unclosed)");
  }, "sql/unterminated-quote");
  rejects("b.safeSql.assertSingleStatement refuses unbalanced parens", function () {
    b.safeSql.assertSingleStatement("CREATE TABLE t (id INTEGER");
  }, "sql/unbalanced");

  // ---- b.guardSql surface (the SQL guard composed by b.sql for raw frags) ----
  check("b.guardSql.validate", b.guardSql.validate("id = ? AND x = ?").ok === true);
  check("b.guardSql.validate hostile", b.guardSql.validate("1; DROP TABLE t", { profile: "strict" }).ok === false);
  check("b.guardSql.sanitize", typeof b.guardSql.sanitize("id = ?") === "string");
  check("b.guardSql.gate", typeof b.guardSql.gate === "function");
  check("b.guardSql.buildProfile", typeof b.guardSql.buildProfile === "function");
  check("b.guardSql.compliancePosture", b.guardSql.compliancePosture("hipaa") !== undefined);
  check("b.guardSql.loadRulePack", typeof b.guardSql.loadRulePack === "function");
  check("b.guardSql.GuardSqlError", typeof b.guardSql.GuardSqlError === "function");

  // ---- b.frameworkSchema coercion (BIGINT-string -> Number, BYTEA -> Buffer) ----
  check("b.frameworkSchema.coerceRow", typeof b.frameworkSchema.coerceRow === "function");
  check("b.frameworkSchema.coerceRows", Array.isArray(b.frameworkSchema.coerceRows([])));

  // ---- safeSql composition ----
  check("quoteIdentifier pg",     safeSql.quoteIdentifier("createdAt", "postgres") === '"createdAt"');
  check("quoteIdentifier mysql",  safeSql.quoteIdentifier("createdAt", "mysql") === "`createdAt`");
  check("quoteList",              safeSql.quoteList(["a", "b"], "postgres") === '"a", "b"');
  check("countPlaceholders",      safeSql.countPlaceholders("a = ? AND b = ?") === 2);
  check("countPlaceholders skips literal",
        safeSql.countPlaceholders("note = 'has ? inside' AND id = ?") === 1);

  // ---- SELECT across dialects ----
  var selPg = sql.select("users", { dialect: "postgres" })
    .columns(["id", "email"]).where("status", "active")
    .orderBy("createdAt", "desc").limit(10).toSql();
  check("select pg quotes + placeholder",
        selPg.sql === 'SELECT "id", "email" FROM users WHERE "status" = ? ORDER BY "createdAt" DESC LIMIT 10' &&
        selPg.params.length === 1 && selPg.params[0] === "active");
  var selMy = sql.select("users", { dialect: "mysql" }).columns(["id"]).where("id", 1).toSql();
  check("select mysql backticks", selMy.sql === "SELECT `id` FROM users WHERE `id` = ?");

  // ---- INSERT / UPDATE / DELETE ----
  var ins = sql.insert("users").values({ id: 1, email: "a@b.c" }).returning(["id"]).toSql();
  check("insert shape", ins.sql.indexOf("INSERT INTO users") === 0 &&
        ins.sql.indexOf("VALUES (?, ?)") !== -1 && ins.params.length === 2);
  var upd = sql.update("users").set({ status: "off" }).where("id", 1).toSql();
  check("update shape", upd.sql === 'UPDATE users SET "status" = ? WHERE "id" = ?' &&
        upd.params.length === 2);
  rejects("update without where throws", function () {
    return sql.update("users").set({ status: "off" }).toSql();
  }, "sql-builder/no-where");
  check("delete with where", sql.delete("sessions").where("id", 1).toSql().params.length === 1);
  rejects("delete without where throws", function () {
    return sql.delete("sessions").toSql();
  }, "sql-builder/no-where");

  // ---- where family: operator allowlist + IN expansion + BETWEEN + LIKE ----
  rejects("bad operator rejected", function () {
    return sql.select("t").where("c", "EVIL", 1).toSql();
  }, "sql-builder/bad-operator");
  var inq = sql.select("t").whereIn("id", [1, 2, 3]).toSql();
  check("IN expands to (?, ?, ?)", inq.sql.indexOf("IN (?, ?, ?)") !== -1 && inq.params.length === 3);
  rejects("empty IN rejected", function () {
    return sql.select("t").whereIn("id", []).toSql();
  }, "sql-builder/empty-in");
  var likeq = sql.select("t").where("name", "LIKE", "50%_off").toSql();
  check("LIKE escapes wildcards with ~", likeq.sql.indexOf("ESCAPE '~'") !== -1 &&
        likeq.params[0].indexOf("~%") !== -1 && likeq.params[0].indexOf("~_") !== -1);

  // ---- NULL-equality footgun: `col = NULL` is UNKNOWN in SQL ----
  rejects("where(col, '=', null) refused (use whereNull)", function () {
    return sql.select("t").where("c", "=", null).toSql();
  }, "sql-builder/null-equality");
  rejects("where({ col: null }) refused (object form is = null)", function () {
    return sql.select("t").where({ c: null }).toSql();
  }, "sql-builder/null-equality");
  var isNullq = sql.select("t").whereNull("c").toSql();
  check("whereNull emits IS NULL with no bound param",
        isNullq.sql.indexOf('"c" IS NULL') !== -1 && isNullq.params.length === 0);

  // ---- whereInArray: per-element validation parity across dialects ----
  rejects("whereInArray undefined element refused (PG = ANY would bind it silently)", function () {
    return sql.select("t", { dialect: "postgres" }).whereInArray("id", [1, undefined, 3]).toSql();
  }, "sql-builder/bad-in-value");
  var anyq = sql.select("t", { dialect: "postgres" }).whereInArray("id", [1, 2]).toSql();
  check("whereInArray PG path binds the array as one = ANY(?) param",
        anyq.sql.indexOf("= ANY(?)") !== -1 && anyq.params.length === 1);

  // ---- JSONB guard + jsonb_exists emission (inherited from db-query) ----
  var jc = sql.select("docs", { dialect: "postgres" }).where("meta", "@>", { a: 1 }).toSql();
  check("@> binds canonical JSON", jc.sql.indexOf('"meta" @> ?') !== -1 && jc.params[0] === '{"a":1}');
  var jk = sql.select("docs", { dialect: "postgres" }).where("meta", "?", "akey").toSql();
  check("? -> jsonb_exists", jk.sql.indexOf('jsonb_exists("meta", ?)') !== -1 && jk.params[0] === "akey");
  var jka = sql.select("docs", { dialect: "postgres" }).where("meta", "?|", ["a", "b"]).toSql();
  check("?| -> jsonb_exists_any", jka.sql.indexOf('jsonb_exists_any("meta", ?)') !== -1);
  var jkb = sql.select("docs", { dialect: "postgres" }).where("meta", "?&", ["a", "b"]).toSql();
  check("?& -> jsonb_exists_all", jkb.sql.indexOf('jsonb_exists_all("meta", ?)') !== -1);
  rejects("NUL JSONB key rejected", function () {
    return sql.select("docs", { dialect: "postgres" }).where("meta", "?", "a" + NUL + "b").toSql();
  }, "safe-jsonpath/key-control-char");
  // Dialect-design gate: JSONB ops are Postgres-only; emitting them for a
  // sqlite / mysql backend would regress downstream (no jsonb_exists / @>).
  rejects("@> on sqlite rejected (postgres-only)", function () {
    return sql.select("docs", { dialect: "sqlite" }).where("meta", "@>", { a: 1 }).toSql();
  }, "sql-builder/jsonb-postgres-only");
  rejects("? on mysql rejected (postgres-only)", function () {
    return sql.select("docs", { dialect: "mysql" }).where("meta", "?", "k").toSql();
  }, "sql-builder/jsonb-postgres-only");

  // ---- output validator boundaries (_assertEmittable) ----
  rejects("NUL in string param", function () {
    return sql.insert("t").values({ a: "x" + NUL + "y" }).toSql();
  }, "sql-builder/null-byte-param");
  rejects("lone surrogate param", function () {
    return sql.insert("t").values({ a: "x" + LONE + "y" }).toSql();
  }, "sql-builder/invalid-encoding-param");
  rejects("oversized buffer param", function () {
    return sql.insert("t").values({ a: Buffer.alloc(64 * 1024 * 1024 + 1) }).toSql();
  }, "sql-builder/param-too-large");
  rejects("undefined param value", function () {
    return sql.insert("t").values({ a: undefined }).toSql();
  }, "sql-builder/bad-param-value");
  // A normal-size buffer + spaced strings must PASS (no false rejection).
  var okBuf = sql.insert("blobs").values({ id: 1, data: Buffer.from("hello world, spaced") }).toSql();
  check("normal buffer + spaced string passes", okBuf.params.length === 2);

  // ---- DDL (terminal: return { sql, params } directly) ----
  var ct = sql.createTable("widgets", [
    { name: "id", type: "text", primaryKey: true },
    { name: "qty", type: "int" },
  ], { dialect: "postgres" });
  check("createTable quotes cols + maps logical type",
        ct.sql.indexOf("CREATE TABLE") === 0 && ct.sql.indexOf("widgets") !== -1 &&
        ct.sql.indexOf('"id"') !== -1 && ct.sql.indexOf("BIGINT") !== -1);
  var dt = sql.dropTable("widgets", { dialect: "postgres" });
  check("dropTable", dt.sql.indexOf("DROP TABLE") === 0 && dt.sql.indexOf("widgets") !== -1);

  // ---- upsert (dialect-final) ----
  var upPg = sql.upsert("kv", { dialect: "postgres" }).columns(["k", "v"]).values({ k: "a", v: "b" })
    .onConflict(["k"]).doUpdateFromExcluded(["v"]).toSql();
  check("upsert pg ON CONFLICT", upPg.sql.indexOf("ON CONFLICT") !== -1 &&
        upPg.sql.indexOf("DO UPDATE") !== -1);

  // ==== dialect-design divergence (Postgres vs SQLite vs MySQL) ====
  // Each construct below emits a different form per dialect; a regression
  // that leaks one dialect's form to another backend would ship green
  // without these (b.sql is a pure composer with no live driver in-test).
  var cs = b.clusterStorage;

  // Sub-query composition: a sub built with a different dialect than the
  // parent has eagerly baked the wrong quote char -> refuse loudly rather
  // than splice mixed quoting the backend mis-reads. (IN / EXISTS / whereSub
  // / selectSub / CTE all route through the same compose gate.)
  rejects("IN subquery dialect mismatch", function () {
    return sql.select("u", { dialect: "mysql" }).whereIn("id", sql.select("o").columns(["uid"])).toSql();
  }, "sql-builder/dialect-mismatch");
  rejects("CTE body dialect mismatch", function () {
    return sql.select("u", { dialect: "mysql" }).with("r", sql.select("o").columns(["uid"]))
      .columns(["id"]).toSql();
  }, "sql-builder/dialect-mismatch");
  var inMatch = sql.select("u", { dialect: "mysql" })
    .whereIn("id", sql.select("o", { dialect: "mysql" }).columns(["uid"])).toSql();
  check("IN subquery same-dialect composes (backtick body)",
        inMatch.sql.indexOf("`uid`") !== -1 && inMatch.sql.indexOf('"uid"') === -1);
  var inDefault = sql.select("u").whereIn("id", sql.select("o").columns(["uid"])).toSql();
  check("default+default subquery composes", inDefault.sql.indexOf("IN (SELECT") !== -1);

  // placeholderize skip-set is a superset of countPlaceholders': a ? inside
  // a double-quoted identifier or a comment must NOT be renumbered to $N.
  check("placeholderize skips ? in ident + comment",
        cs.placeholderize('SELECT "c?l" FROM t WHERE id = ? -- k?v', "postgres") ===
        'SELECT "c?l" FROM t WHERE id = $1 -- k?v');
  check("placeholderize renumbers real binds",
        cs.placeholderize("a = ? AND b = ?", "postgres") === "a = $1 AND b = $2");

  // DDL type mapping: json -> JSONB (pg) / JSON (mysql) / TEXT (sqlite).
  check("json type pg JSONB",
        sql.createTable("d", [{ name: "j", type: "json" }], { dialect: "postgres" }).sql.indexOf("JSONB") !== -1);
  check("json type mysql JSON",
        sql.createTable("d", [{ name: "j", type: "json" }], { dialect: "mysql" }).sql.indexOf(" JSON") !== -1);
  check("json type sqlite TEXT",
        sql.createTable("d", [{ name: "j", type: "json" }], { dialect: "sqlite" }).sql.indexOf("TEXT") !== -1);

  // Auto-increment identity PK diverges per dialect (else an app built on
  // sqlite's implicit INTEGER-PK auto-increment breaks on pg/mysql).
  check("autoIncrement pg BIGSERIAL",
        sql.createTable("t", [{ name: "id", autoIncrement: true }], { dialect: "postgres" })
          .sql.indexOf("BIGSERIAL PRIMARY KEY") !== -1);
  check("autoIncrement sqlite INTEGER AUTOINCREMENT",
        sql.createTable("t", [{ name: "id", autoIncrement: true }], { dialect: "sqlite" })
          .sql.indexOf("INTEGER PRIMARY KEY AUTOINCREMENT") !== -1);
  check("autoIncrement mysql AUTO_INCREMENT",
        sql.createTable("t", [{ name: "id", autoIncrement: true }], { dialect: "mysql" })
          .sql.indexOf("AUTO_INCREMENT") !== -1);

  // RETURNING is unsupported on MySQL for plain verbs -> refuse at build.
  rejects("RETURNING on mysql insert", function () {
    return sql.insert("t", { dialect: "mysql" }).values({ a: 1 }).returning(["a"]).toSql();
  }, "sql-builder/returning-unsupported");
  check("RETURNING on pg insert works",
        sql.insert("t", { dialect: "postgres" }).values({ a: 1 }).returning(["a"]).toSql()
          .sql.indexOf("RETURNING") !== -1);

  // Raw fragment carrying a bare JSONB ?| operator -> refuse (placeholderize
  // would corrupt the operator to $N).
  rejects("raw ?| operator refused", function () {
    return sql.select("t", { dialect: "postgres" }).whereRaw("tags ?| ?", [["a"]]).toSql();
  }, "sql-builder/raw-jsonb-op");

  // LIKE ESCAPE uses ~, not backslash (backslash breaks MySQL default sql_mode).
  check("LIKE ESCAPE is ~ on mysql",
        sql.select("t", { dialect: "mysql" }).where("n", "LIKE", "x%").toSql().sql.indexOf("ESCAPE '~'") !== -1);

  // JSONB operator in a join ON has no jsonb_exists rewrite -> refuse.
  rejects("join ON JSONB operator refused", function () {
    return sql.select("t", { dialect: "postgres" }).join("o", "t.a", "@>", "o.b").toSql();
  }, "sql-builder/jsonb-bad-position");

  // ==== defineTable (PK/FK/index automation) + its dialect divergence ====
  // Identity PK diverges per dialect (the regression that breaks an app
  // built on sqlite when it ships to pg/mysql).
  var dPg = sql.defineTable("orders", [{ name: "userId", type: "int" }], { dialect: "postgres" });
  var dSq = sql.defineTable("orders", [{ name: "userId", type: "int" }], { dialect: "sqlite" });
  var dMy = sql.defineTable("orders", [{ name: "userId", type: "int" }], { dialect: "mysql" });
  check("defineTable pg BIGSERIAL PK", dPg.statements[0].sql.indexOf("BIGSERIAL PRIMARY KEY") !== -1);
  check("defineTable sqlite INTEGER AUTOINCREMENT PK",
        dSq.statements[0].sql.indexOf("INTEGER PRIMARY KEY AUTOINCREMENT") !== -1);
  check("defineTable mysql AUTO_INCREMENT PK", dMy.statements[0].sql.indexOf("AUTO_INCREMENT PRIMARY KEY") !== -1);

  // FK inference + per-dialect quoting (double-quote pg/sqlite, backtick mysql).
  check("defineTable FK inference pg quoting",
        dPg.statements[0].sql.indexOf('"userId" BIGINT REFERENCES users ("id")') !== -1);
  check("defineTable FK inference mysql backtick quoting",
        dMy.statements[0].sql.indexOf("`userId` BIGINT REFERENCES users (`id`)") !== -1);
  check("defineTable pluralize categoryId -> categories",
        sql.defineTable("o", [{ name: "categoryId", type: "int" }], { dialect: "postgres" })
          .statements[0].sql.indexOf("REFERENCES categories") !== -1);

  // Auto-index the FK column, quoted in the table's dialect (a regression
  // where the index leaks the wrong quote char breaks the wrong backend).
  check("defineTable auto-index FK pg", dPg.statements.some(function (s) {
    return s.sql.indexOf("CREATE INDEX") === 0 && s.sql.indexOf('("userId")') !== -1; }));
  check("defineTable auto-index FK mysql backtick", dMy.statements.some(function (s) {
    return s.sql.indexOf("CREATE INDEX") === 0 && s.sql.indexOf("(`userId`)") !== -1; }));

  // json column type diverges through defineTable too.
  check("defineTable json type mysql JSON",
        sql.defineTable("d", [{ name: "j", type: "json" }], { dialect: "mysql" })
          .statements[0].sql.indexOf(" JSON") !== -1);

  // Disable knobs.
  check("defineTable autoForeignKeys:false drops FK + index",
        sql.defineTable("t", [{ name: "id", autoIncrement: true }, { name: "userId", type: "int" }],
          { dialect: "postgres", autoForeignKeys: false }).statements.length === 1);
  check("defineTable autoIndex:false drops indexes",
        sql.defineTable("t", [{ name: "id", autoIncrement: true }, { name: "userId", type: "int" }],
          { dialect: "postgres", autoIndex: false }).statements.length === 1);
  var optOut = sql.defineTable("t", [{ name: "id", autoIncrement: true },
    { name: "userId", type: "int", references: false }], { dialect: "postgres" });
  check("defineTable references:false opts out of FK",
        optOut.statements.length === 1 && optOut.statements[0].sql.indexOf("REFERENCES") === -1);

  // Column-namespace gate (same discipline as the query builder): an index
  // on a non-declared column is refused.
  rejects("defineTable index on unknown column", function () {
    return sql.defineTable("t", [{ name: "id", autoIncrement: true }],
      { dialect: "postgres", indexes: [{ columns: ["ghost"] }] });
  }, "sql-builder/unknown-column");

  // FK referential actions allowlisted.
  check("defineTable FK onDelete CASCADE",
        sql.defineTable("t", [{ name: "id", autoIncrement: true },
          { name: "userId", type: "int", references: { table: "users", onDelete: "cascade" } }],
          { dialect: "postgres" }).statements[0].sql.indexOf("ON DELETE CASCADE") !== -1);
  rejects("defineTable FK bad referential action", function () {
    return sql.defineTable("t", [{ name: "id", autoIncrement: true },
      { name: "userId", type: "int", references: { table: "users", onDelete: "explode" } }],
      { dialect: "postgres" });
  }, "sql-builder/bad-fk-action");

  // Generated index name bounded to the identifier limit (like every
  // query-builder identifier).
  var longCol = new Array(61).join("c");   // 60-char valid identifier
  var longDef = sql.defineTable("orders", [{ name: "id", autoIncrement: true },
    { name: longCol, type: "text", index: true }], { dialect: "postgres" });
  var longIdx = longDef.statements.filter(function (s) { return s.sql.indexOf("CREATE INDEX") === 0; })[0];
  var idxNameMatch = /INDEX IF NOT EXISTS "([^"]+)"/.exec(longIdx.sql);
  check("defineTable index name within identifier limit",
        idxNameMatch !== null && idxNameMatch[1].length <= 63);

  // ==== v0.15.0 direct-driver + value-cell + RLS + catalog surface ====
  // These primitives make the b.outbox / b.inbox / b.db.declareRowPolicy
  // migrations possible (those targets hand SQL to an operator driver
  // directly, with no clusterStorage in the path).

  check("b.sql.fn",            typeof b.sql.fn === "function");
  check("b.sql.cast",          typeof b.sql.cast === "function");
  check("b.sql.toExternalSql", typeof b.sql.toExternalSql === "function");
  check("b.sql.enableRowLevelSecurity",  typeof b.sql.enableRowLevelSecurity === "function");
  check("b.sql.disableRowLevelSecurity", typeof b.sql.disableRowLevelSecurity === "function");
  check("b.sql.createPolicy",  typeof b.sql.createPolicy === "function");
  check("b.sql.dropPolicy",    typeof b.sql.dropPolicy === "function");
  check("b.sql.pragma",        typeof b.sql.pragma === "function");
  check("b.sql.catalog",       b.sql.catalog && typeof b.sql.catalog.listTables === "function");

  // ---- toExternalSql: ? -> $N on postgres, unchanged on sqlite/mysql ----
  var pgExt = sql.select("t", { dialect: "postgres" }).where("a", 1).where("b", 2).toExternalSql("postgres");
  check("toExternalSql postgres $N", pgExt.sql.indexOf("$1") !== -1 && pgExt.sql.indexOf("$2") !== -1 &&
        pgExt.sql.indexOf("?") === -1);
  var liteExt = sql.select("t", { dialect: "sqlite" }).where("a", 1).toExternalSql("sqlite");
  check("toExternalSql sqlite keeps ?", liteExt.sql.indexOf("?") !== -1 && liteExt.sql.indexOf("$1") === -1);
  // A `?` inside a string literal is NOT a placeholder (quote-aware pass).
  var litFrag = sql.select("t", { dialect: "postgres" })
    .whereRaw("note = 'has a ? mark'", [], { allowLiterals: true }).where("id", 1).toExternalSql("postgres");
  check("toExternalSql skips ? inside literal", /'has a \? mark'/.test(litFrag.sql) &&
        litFrag.sql.indexOf("$1") !== -1 && litFrag.sql.indexOf("$2") === -1);
  // Standalone toExternalSql wrapper over a DDL { sql, params } result.
  var ddlExt = b.sql.toExternalSql(
    b.sql.createIndex("idx_p", "outbox", ["next_attempt_at"],
      { dialect: "postgres", where: "status = 'pending'" }), "postgres");
  check("toExternalSql wraps DDL result", ddlExt.sql.indexOf("WHERE status = 'pending'") !== -1);
  rejects("toExternalSql rejects non-builder/non-result", function () {
    return b.sql.toExternalSql(42, "postgres");
  }, "sql-builder/bad-external-input");

  // ---- fn / cast value cells in INSERT + UPDATE ----
  var fnIns = sql.insert("events", { dialect: "postgres" })
    .values({ topic: "x", at: sql.fn("NOW") }).toSql();
  check("insert fn(NOW) emits token no param",
        /VALUES \(\?, NOW\(\)\)/.test(fnIns.sql) && fnIns.params.length === 1);
  var castIns = sql.insert("docs", { dialect: "postgres" })
    .values({ id: 1, meta: sql.cast('{"a":1}', "jsonb") }).toSql();
  check("insert cast(::jsonb) binds value + casts placeholder",
        /\?::jsonb/.test(castIns.sql) && castIns.params.length === 2 && castIns.params[1] === '{"a":1}');
  var fnUpd = sql.update("t", { dialect: "postgres" })
    .set({ updated_at: sql.fn("CURRENT_TIMESTAMP") }).where("id", 1).toSql();
  check("update set fn(CURRENT_TIMESTAMP) no param for the cell",
        /SET "updated_at" = CURRENT_TIMESTAMP/.test(fnUpd.sql) && fnUpd.params.length === 1);
  rejects("fn rejects non-allowlisted function", function () { return sql.fn("EVIL"); },
    "sql-builder/bad-fn");
  rejects("cast rejects non-allowlisted type", function () { return sql.cast("x", "regclass"); },
    "sql-builder/bad-cast");
  // Postgres-only cast has no portable form on sqlite -> throws at build.
  rejects("cast interval is postgres-only on sqlite", function () {
    return sql.insert("t", { dialect: "sqlite" }).values({ d: sql.cast("1 day", "interval") }).toSql();
  }, "sql-builder/cast-unsupported");

  // upsert VALUES routes through the value-cell choke-point too (the inbox
  // ON CONFLICT DO NOTHING RETURNING dedup carries NOW() + ::jsonb cells).
  var upFn = sql.upsert("inbox", { dialect: "postgres" })
    .columns(["mid", "src", "rcv", "meta"])
    .values({ mid: "m", src: "s", rcv: sql.fn("NOW"), meta: sql.cast(null, "jsonb") })
    .onConflict(["src", "mid"]).doNothing().returning(["mid"]).toSql();
  check("upsert VALUES renders fn + cast cells",
        /VALUES \(\?, \?, NOW\(\), \?::jsonb\)/.test(upFn.sql) &&
        /DO NOTHING RETURNING "mid"/.test(upFn.sql) && upFn.params.length === 3);

  // ---- whereInArray: = ANY(?) on postgres, IN (?, ...) on sqlite ----
  var anyPg = sql.update("t", { dialect: "postgres" }).set({ s: "x" }).whereInArray("id", [1, 2, 3]).toSql();
  check("whereInArray = ANY(?) on postgres binds the array as one param",
        /"id" = ANY\(\?\)/.test(anyPg.sql) && anyPg.params.length === 2 &&
        Array.isArray(anyPg.params[1]) && anyPg.params[1].length === 3);
  var anyLite = sql.update("t", { dialect: "sqlite" }).set({ s: "x" }).whereInArray("id", [1, 2, 3]).toSql();
  check("whereInArray expands to IN(?,?,?) on sqlite",
        /"id" IN \(\?, \?, \?\)/.test(anyLite.sql) && anyLite.params.length === 4);
  rejects("whereInArray rejects empty array", function () {
    return sql.update("t", { dialect: "postgres" }).set({ s: "x" }).whereInArray("id", []).toSql();
  }, "sql-builder/empty-in");

  // ---- forUpdate [SKIP LOCKED] (postgres/mysql); refused on sqlite ----
  var fu = sql.select("q", { dialect: "postgres" }).where("status", "pending")
    .orderBy("at").limit(10).forUpdate({ skipLocked: true }).toSql();
  check("forUpdate skipLocked emits FOR UPDATE SKIP LOCKED",
        /FOR UPDATE SKIP LOCKED$/.test(fu.sql));
  var fuNoWait = sql.select("q", { dialect: "postgres" }).forUpdate({ noWait: true }).toSql();
  check("forUpdate noWait emits FOR UPDATE NOWAIT", /FOR UPDATE NOWAIT$/.test(fuNoWait.sql));
  check("forShare emits FOR SHARE",
        /FOR SHARE$/.test(sql.select("q", { dialect: "postgres" }).forShare().toSql().sql));
  rejects("forUpdate refused on sqlite", function () {
    return sql.select("q", { dialect: "sqlite" }).forUpdate().toSql();
  }, "sql-builder/lock-unsupported");
  rejects("forUpdate skipLocked + noWait mutually exclusive", function () {
    return sql.select("q", { dialect: "postgres" }).forUpdate({ skipLocked: true, noWait: true });
  }, "sql-builder/bad-lock");

  // ---- partial index (createIndex { where }) ----
  var partial = sql.createIndex("idx_pending", "outbox", ["at"],
    { dialect: "postgres", where: "status = 'pending'" });
  check("createIndex partial WHERE", /WHERE status = 'pending'$/.test(partial.sql));
  rejects("createIndex partial WHERE refused on mysql", function () {
    return sql.createIndex("idx_p", "t", ["c"], { dialect: "mysql", where: "x = 1" });
  }, "sql-builder/partial-index-unsupported");

  // ---- RLS builders (postgres-only) ----
  check("enableRowLevelSecurity",
        /ALTER TABLE "public"\."sessions" ENABLE ROW LEVEL SECURITY/.test(
          sql.enableRowLevelSecurity("sessions", { schema: "public", dialect: "postgres" }).sql));
  check("enableRowLevelSecurity force",
        /FORCE ROW LEVEL SECURITY/.test(
          sql.enableRowLevelSecurity("sessions", { dialect: "postgres", force: true }).sql));
  check("disableRowLevelSecurity",
        /DISABLE ROW LEVEL SECURITY/.test(
          sql.disableRowLevelSecurity("sessions", { dialect: "postgres" }).sql));
  var pol = sql.createPolicy("tenant_iso", "sessions", {
    role: "app_user", command: "ALL",
    using: "tenant_id = current_setting('app.tenant_id')::uuid",
    withCheck: "tenant_id = current_setting('app.tenant_id')::uuid",
  }, { schema: "public", dialect: "postgres" });
  check("createPolicy canonical clause order",
        /CREATE POLICY "tenant_iso" ON "public"\."sessions" AS PERMISSIVE FOR ALL TO "app_user" USING \(/.test(pol.sql) &&
        /WITH CHECK \(/.test(pol.sql));
  check("dropPolicy IF EXISTS",
        /DROP POLICY IF EXISTS "tenant_iso" ON "public"\."sessions"/.test(
          sql.dropPolicy("tenant_iso", "sessions", { schema: "public", dialect: "postgres" }).sql));
  rejects("createPolicy requires using", function () {
    return sql.createPolicy("p", "t", { command: "ALL" }, { dialect: "postgres" });
  }, "sql-builder/bad-rls-predicate");
  rejects("enableRowLevelSecurity refused on sqlite", function () {
    return sql.enableRowLevelSecurity("t", { dialect: "sqlite" });
  }, "sql-builder/rls-postgres-only");

  // ---- catalog / pragma audited sub-API (sqlite-internal) ----
  check("catalog.listTables",
        /SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'/.test(
          sql.catalog.listTables().sql));
  check("catalog.tableExists binds name",
        sql.catalog.tableExists("audit_log").params[0] === "audit_log");
  check("catalog.tableInfo quotes name",
        /PRAGMA table_info\("audit_log"\)/.test(sql.catalog.tableInfo("audit_log").sql));
  check("catalog.sampleRandom ORDER BY RANDOM",
        /ORDER BY RANDOM\(\) LIMIT \?/.test(sql.catalog.sampleRandom("t", ["a"], { limit: 5 }).sql));
  check("catalog.changes", sql.catalog.changes().sql === "SELECT changes() AS c");
  check("pragma journal_mode set", sql.pragma("journal_mode", "WAL").sql === "PRAGMA journal_mode=WAL");
  check("pragma journal_mode read", sql.pragma("journal_mode").sql === "PRAGMA journal_mode");
  check("pragma wal_checkpoint", sql.pragma("wal_checkpoint", "TRUNCATE").sql === "PRAGMA wal_checkpoint(TRUNCATE)");
  rejects("pragma rejects off-allowlist verb", function () { return sql.pragma("user_version", 5); },
    "sql-builder/bad-pragma");
  rejects("pragma rejects off-vocabulary arg", function () { return sql.pragma("journal_mode", "EVIL"); },
    "sql-builder/bad-pragma-arg");

  // ---- selectRaw projection (presence sentinel) ----
  var probe = sql.select("t", { dialect: "postgres" }).selectRaw("1").where("id", 1).toExternalSql("postgres");
  check("selectRaw 1 presence probe", /^SELECT 1 FROM t WHERE "id" = \$1$/.test(probe.sql));

  // ---- sqlite FTS5 virtual table DDL (createVirtualTable) ----
  var vt = sql.createVirtualTable("mail_fts", {
    columns:  [{ name: "objectid", unindexed: true }, "subject_toks", "body_toks"],
    tokenize: "unicode61 remove_diacritics 2",
  });
  check("createVirtualTable emits USING fts5 with quoted cols + tokenize",
        vt.sql === 'CREATE VIRTUAL TABLE IF NOT EXISTS "mail_fts" USING fts5(' +
          '"objectid" UNINDEXED, "subject_toks", "body_toks", ' +
          "tokenize = 'unicode61 remove_diacritics 2')");
  rejects("createVirtualTable refused on non-sqlite", function () {
    return sql.createVirtualTable("x", { columns: ["a"], dialect: "postgres" });
  }, "sql-builder/vtable-sqlite-only");
  rejects("createVirtualTable refuses loadable tokenizer", function () {
    return sql.createVirtualTable("x", { columns: ["a"], tokenize: "evil_loadable" });
  }, "sql-builder/bad-tokenize");
  rejects("createVirtualTable refuses off-allowlist tokenize arg", function () {
    return sql.createVirtualTable("x", { columns: ["a"], tokenize: "unicode61 DROP" });
  }, "sql-builder/bad-tokenize");
  rejects("createVirtualTable refuses unknown per-column option", function () {
    return sql.createVirtualTable("x", { columns: [{ name: "a", evil: 1 }] });
  }, "sql-builder/bad-vtable-column");

  // ---- FTS5 MATCH (whereMatch) — operand always binds as a single ? ----
  var m = sql.select("mail_fts", { dialect: "sqlite" }).columns(["objectid"])
    .whereMatch("mail_fts", "hashA hashB").toSql();
  check("whereMatch emits <table> MATCH ? binding the query string",
        m.sql === 'SELECT "objectid" FROM mail_fts WHERE "mail_fts" MATCH ?' &&
          m.params.length === 1 && m.params[0] === "hashA hashB");
  rejects("whereMatch refused on postgres", function () {
    return sql.select("t", { dialect: "postgres" }).columns(["id"]).whereMatch("t", "x").toSql();
  }, "sql-builder/match-sqlite-only");
  rejects("whereMatch refuses empty query", function () {
    return sql.select("t", { dialect: "sqlite" }).columns(["id"]).whereMatch("t", "").toSql();
  }, "sql-builder/bad-match");

  // ---- json_each membership (whereInJsonEach) — JSON-array string binds as one ? ----
  var je = sql.select("msgs", { dialect: "sqlite" }).columns(["objectid", "folder_id"])
    .where("folder_id", 1).whereInJsonEach("objectid", '["a","b"]').toSql();
  check("whereInJsonEach emits IN (SELECT value FROM json_each(?))",
        je.sql.indexOf('"objectid" IN (SELECT value FROM json_each(?))') !== -1 &&
          je.params.length === 2 && je.params[1] === '["a","b"]');
  rejects("whereInJsonEach refused on postgres", function () {
    return sql.select("t", { dialect: "postgres" }).columns(["id"]).whereInJsonEach("id", "[]").toSql();
  }, "sql-builder/json-each-sqlite-only");

  // ---- the composed mail-store search shape: FTS subquery driving an
  // outer SELECT via whereIn(col, subBuilder) ----
  var ftsSub = sql.select("mail_fts", { dialect: "sqlite" }).columns(["objectid"])
    .whereMatch("mail_fts", "tok1 tok2");
  var search = sql.select("msgs", { dialect: "sqlite" }).columns(["objectid", "modseq"])
    .where("folder_id", 1).whereOp("modseq", ">", 5).whereIn("objectid", ftsSub)
    .orderBy("modseq").limit(50).toSql();
  check("FTS subquery composes into outer whereIn with one MATCH bind + folder/modseq binds",
        /MATCH \?\) ORDER BY "modseq" ASC LIMIT 50$/.test(search.sql) &&
          search.params.length === 3 &&
          search.params[0] === 1 && search.params[1] === 5 && search.params[2] === "tok1 tok2");

  // ---- v0.15.3 DDL hardening ----
  // #105 verbatim column type: the one raw-emission position in the builder.
  // Injection safety is enforced at the statement level — createTable routes the
  // finished DDL through the quote-aware _assertCatalogEmittable, which refuses a
  // top-level ';' / comment / unbalanced quote / unbalanced paren while allowing
  // those characters INSIDE a balanced quoted label (so MySQL ENUM/SET pass).
  rejects("createTable refuses a verbatim type that stacks a statement", function () {
    return sql.createTable("t", [{ name: "id", type: "int" },
      { name: "evil", type: "text); DROP TABLE secrets; --" }], { dialect: "postgres" });
  }, "sql-builder/stacked-statement");
  rejects("createTable refuses a verbatim type with an unbalanced quote (catalog gate)", function () {
    return sql.createTable("t", [{ name: "c", type: "text'" }], { dialect: "postgres" });
  }, "sql-builder/unterminated-quote");
  check("createTable allows a MySQL ENUM type (balanced quotes, the verbatim fallthrough)",
        sql.createTable("t", [{ name: "id", type: "int" }, { name: "status", type: "ENUM('active','inactive')" }],
          { dialect: "mysql" }).sql.indexOf("ENUM('active','inactive')") !== -1);
  check("createTable allows a marker (;/--) INSIDE a balanced ENUM label (quote-aware gate, not over-rejected)",
        sql.createTable("t", [{ name: "id", type: "int" }, { name: "status", type: "ENUM('needs;review','a--b')" }],
          { dialect: "mysql" }).sql.indexOf("ENUM('needs;review','a--b')") !== -1);
  check("createTable allows a legit multi-word verbatim type (DOUBLE PRECISION)",
        sql.createTable("t", [{ name: "id", type: "int" }, { name: "p", type: "DOUBLE PRECISION" }],
          { dialect: "postgres" }).sql.indexOf("DOUBLE PRECISION") !== -1);
  check("createTable allows a parameterised verbatim type (VARCHAR(255))",
        sql.createTable("t", [{ name: "s", type: "VARCHAR(255)" }], { dialect: "postgres" })
          .sql.indexOf("VARCHAR(255)") !== -1);

  // #118 a column-level primary key and a composite opts.primaryKey are exclusive.
  rejects("createTable refuses a column PK plus a composite opts.primaryKey", function () {
    return sql.createTable("t", [{ name: "id", autoIncrement: true }, { name: "k", type: "text" }],
      { dialect: "sqlite", primaryKey: ["id", "k"] });
  }, "sql-builder/bad-column");
  check("createTable allows a composite opts.primaryKey with no column-level PK",
        sql.createTable("t", [{ name: "a", type: "int" }, { name: "b", type: "int" }],
          { dialect: "sqlite", primaryKey: ["a", "b"] }).sql.indexOf('PRIMARY KEY ("a", "b")') !== -1);

  // #119 upsert readback resolves the conflict-key cell instead of binding a wrapper.
  rejects("upsert readback refuses a server-evaluated function conflict key", function () {
    return sql.upsert("t", { dialect: "mysql" }).values({ id: sql.fn("CURRENT_TIMESTAMP"), c: 1 })
      .onConflict(["id"]).doUpdateFromExcluded(["c"]).returning(["c"]).toSql();
  }, "sql-builder/bad-conflict");
  var rbScalar = sql.upsert("t", { dialect: "mysql" }).values({ id: 5, c: 1 })
    .onConflict(["id"]).doUpdateFromExcluded(["c"]).returning(["c"]).toSql();
  check("upsert readback binds a plain scalar conflict key unchanged",
        rbScalar.readbackSql && rbScalar.readbackSql.params.length === 1 &&
          rbScalar.readbackSql.params[0] === 5);
  var rbCast = sql.upsert("t", { dialect: "mysql" }).values({ id: sql.cast("42", "int"), c: 1 })
    .onConflict(["id"]).doUpdateFromExcluded(["c"]).returning(["c"]).toSql();
  check("upsert readback renders a cast conflict key (CAST) binding the inner value, not the wrapper",
        rbCast.readbackSql && rbCast.readbackSql.sql.indexOf("CAST(") !== -1 &&
          rbCast.readbackSql.params.length === 1 && rbCast.readbackSql.params[0] === "42");

  // ==== insertSelectWhere (conditional INSERT...SELECT...WHERE, #335) ====
  // The append-only-ledger debit: a row written ONLY when a guard derived
  // from the table itself holds, with no mutable counter row to increment().
  // Standard SQL across all three dialects; the SELECT is value-less and the
  // WHERE admits one row or zero.

  // Object-form values infer the column list; the guard is an EXISTS over a
  // same-dialect sub-builder (the balance fence). The cells route through the
  // value-cell choke-point (fn(NOW) emits a token, no param).
  var ledgerBalance = sql.select("wallet_ledger", { dialect: "postgres" }).selectRaw("1")
    .whereRaw('"wallet_id" = ?', ["w-1"]);
  var debit = sql.insertSelectWhere("wallet_ledger", { dialect: "postgres" })
    .values({ wallet_id: "w-1", amount: -25, at: sql.fn("NOW") })
    .whereExists(ledgerBalance)
    .returning(["id"]).toSql();
  check("insertSelectWhere emits INSERT...SELECT cells...WHERE EXISTS...RETURNING",
        debit.sql === 'INSERT INTO wallet_ledger ("wallet_id", "amount", "at") ' +
          'SELECT ?, ?, NOW() WHERE EXISTS (SELECT 1 FROM wallet_ledger WHERE ("wallet_id" = ?)) ' +
          'RETURNING "id"');
  check("insertSelectWhere binds value cells then the guard params in order, fn emits no param",
        debit.params.length === 3 && debit.params[0] === "w-1" &&
          debit.params[1] === -25 && debit.params[2] === "w-1");

  // Positional values() aligned to a prior columns() call, sqlite dialect,
  // a scalar guard (whereOp). No RETURNING -> none emitted.
  var lit = sql.insertSelectWhere("seats", { dialect: "sqlite" })
    .columns(["event_id", "seat_no"]).values(["e-9", 12])
    .whereOp("event_id", "=", "e-9").toSql();
  check("insertSelectWhere positional values + sqlite quoting + scalar guard",
        lit.sql === 'INSERT INTO seats ("event_id", "seat_no") SELECT ?, ? WHERE "event_id" = ?' &&
          lit.params.length === 3 && lit.params[2] === "e-9");

  // cast cell binds value + casts the placeholder (Postgres ?::jsonb).
  var castSel = sql.insertSelectWhere("docs", { dialect: "postgres" })
    .values({ id: 1, meta: sql.cast('{"a":1}', "jsonb") })
    .whereOp("id", "=", 1).toSql();
  check("insertSelectWhere renders a cast SELECT cell (?::jsonb) binding the inner value",
        /SELECT \?, \?::jsonb WHERE "id" = \?/.test(castSel.sql) &&
          castSel.params.length === 3 && castSel.params[1] === '{"a":1}');

  // MySQL: standard form, backtick quoting; RETURNING refused (run an explicit read).
  var my = sql.insertSelectWhere("ledger", { dialect: "mysql" })
    .values({ k: "a", n: 1 }).whereOp("k", "=", "a").toSql();
  check("insertSelectWhere mysql backtick quoting",
        my.sql === "INSERT INTO ledger (`k`, `n`) SELECT ?, ? WHERE `k` = ?");
  rejects("insertSelectWhere RETURNING refused on mysql", function () {
    return sql.insertSelectWhere("ledger", { dialect: "mysql" })
      .values({ k: "a" }).whereOp("k", "=", "a").returning(["k"]).toSql();
  }, "sql-builder/returning-unsupported");

  // Safety default: an un-guarded conditional insert THROWS (like update/delete);
  // allowNoWhere() opts in deliberately.
  rejects("insertSelectWhere without where throws (no-where default)", function () {
    return sql.insertSelectWhere("ledger").values({ k: "a", n: 1 }).toSql();
  }, "sql-builder/no-where");
  var noWhere = sql.insertSelectWhere("ledger").values({ k: "a", n: 1 }).allowNoWhere().toSql();
  check("insertSelectWhere allowNoWhere() emits a guard-less SELECT",
        noWhere.sql === 'INSERT INTO ledger ("k", "n") SELECT ?, ?' && noWhere.params.length === 2);

  // No values() -> empty-values; values() missing a declared column -> missing-column;
  // an extra key not in the declared column set -> extra-column (no silent data drop).
  rejects("insertSelectWhere without values throws", function () {
    return sql.insertSelectWhere("ledger").columns(["k"]).whereOp("k", "=", "a").toSql();
  }, "sql-builder/empty-values");
  rejects("insertSelectWhere positional value-count mismatch", function () {
    return sql.insertSelectWhere("ledger").columns(["k", "n"]).values(["only-one"]);
  }, "sql-builder/value-count");
  rejects("insertSelectWhere row missing a declared column", function () {
    return sql.insertSelectWhere("ledger").columns(["k", "n"]).values({ k: "a" });
  }, "sql-builder/missing-column");
  // extra-column only fires against an EXPLICIT column set (an inferred set
  // can't have an extra key) — declare ["k","n"] first, then the ghost key.
  rejects("insertSelectWhere row with an extra column", function () {
    return sql.insertSelectWhere("ledger").columns(["k", "n"]).values({ k: "a", n: 1, ghost: 2 })
      .whereOp("k", "=", "a").toSql();
  }, "sql-builder/extra-column");

  // The output gate still fires: a NUL byte in a bound cell value is refused
  // by _assertEmittable, same as every other verb.
  rejects("insertSelectWhere NUL in a cell value refused by the output gate", function () {
    return sql.insertSelectWhere("ledger").values({ k: "x" + NUL + "y", n: 1 })
      .whereOp("n", "=", 1).toSql();
  }, "sql-builder/null-byte-param");

  // Sub-builder dialect-mismatch is refused (a mysql guard sub spliced into a
  // default-sqlite parent has baked the wrong quote char).
  rejects("insertSelectWhere guard sub dialect-mismatch refused", function () {
    return sql.insertSelectWhere("ledger")
      .values({ k: "a", n: 1 })
      .whereExists(sql.select("other", { dialect: "mysql" }).columns(["id"])).toSql();
  }, "sql-builder/dialect-mismatch");

  // toExternalSql translates ? -> $N on postgres at the boundary (direct-driver path).
  var ext = sql.insertSelectWhere("ledger", { dialect: "postgres" })
    .values({ k: "a", n: 1 }).whereOp("k", "=", "a").toExternalSql("postgres");
  check("insertSelectWhere toExternalSql postgres $N",
        ext.sql.indexOf("$1") !== -1 && ext.sql.indexOf("$2") !== -1 &&
          ext.sql.indexOf("$3") !== -1 && ext.sql.indexOf("?") === -1);
}

module.exports = { run: run };
