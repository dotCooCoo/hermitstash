// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.sql — coverage companion to sql.test.js. Exercises the ordinary
 * builder surface the primary file's dialect-divergence + security focus
 * leaves untested: aggregates, DISTINCT, the JOIN family, GROUP BY /
 * HAVING, ORDER BY / LIMIT / OFFSET validation, the LIKE-mode + BETWEEN +
 * nested-group + EXISTS / scalar-subquery where helpers, CTE composition,
 * setRaw, the column-membership gate modes, the alterTable / dropTable /
 * createIndex option branches, DDL DEFAULT rendering, table-reference
 * shapes, and the fn / cast / casWon / output-gate boundary codes. Every
 * assertion drives the public b.sql surface; no private internals.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function rejects(label, fn, code) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && threw.code === code);
}

async function run() {
  var sql = b.sql;

  // ================= projection: aggregates + DISTINCT =================
  check("count(*) with alias quotes the alias",
        sql.select("t").count("*", "n").toSql().sql === 'SELECT COUNT(*) AS "n" FROM t');
  check("count() defaults col to * (no alias)",
        sql.select("t").count().toSql().sql === "SELECT COUNT(*) FROM t");
  check("countDistinct emits COUNT(DISTINCT col)",
        sql.select("t").countDistinct("email", "c").toSql().sql ===
          'SELECT COUNT(DISTINCT "email") AS "c" FROM t');
  check("max/min/sum/avg each quote their column",
        sql.select("t").max("a").min("b").sum("c").avg("d").toSql().sql ===
          'SELECT MAX("a"), MIN("b"), SUM("c"), AVG("d") FROM t');
  check("distinct() emits SELECT DISTINCT",
        sql.select("t").distinct().columns(["a"]).toSql().sql === 'SELECT DISTINCT "a" FROM t');
  check("aggregate alias is validated (quoted)",
        sql.select("t").count("*", "row_count").toSql().sql.indexOf('AS "row_count"') !== -1);

  // ================= JOIN family =======================================
  var ij = sql.select("u", { alias: "u" }).columns(["u.id"])
    .join(sql.table("orders", { alias: "o" }), "u.id", "=", "o.uid").toSql();
  check("innerJoin quotes both ON operands + emits table alias",
        ij.sql === 'SELECT "u"."id" FROM u "u" INNER JOIN orders "o" ON "u"."id" = "o"."uid"');
  check("leftJoin with a null op defaults to '='",
        sql.select("u").leftJoin("o", "u.id", null, "o.uid").toSql().sql ===
          'SELECT * FROM u LEFT JOIN o ON "u"."id" = "o"."uid"');
  check("rightJoin emits RIGHT JOIN",
        sql.select("u").rightJoin("o", "u.id", "=", "o.uid").toSql().sql.indexOf("RIGHT JOIN") !== -1);
  check("fullJoin emits FULL JOIN",
        sql.select("u").fullJoin("o", "u.id", "=", "o.uid").toSql().sql.indexOf("FULL JOIN") !== -1);
  check("crossJoin emits CROSS JOIN with no ON",
        sql.select("u").crossJoin("o").toSql().sql === "SELECT * FROM u CROSS JOIN o");
  rejects("join without both ON operands refused", function () {
    return sql.select("u").join("o", "u.id").toSql();
  }, "sql-builder/bad-join-on");
  rejects("join with an off-allowlist ON operator refused", function () {
    return sql.select("u").join("o", "u.id", "EVIL", "o.uid").toSql();
  }, "sql-builder/bad-operator");
  check("joinRaw passes a guarded raw join fragment through",
        sql.select("u").joinRaw('INNER JOIN o ON "o"."uid" = "u"."id"').toSql().sql ===
          'SELECT * FROM u INNER JOIN o ON "o"."uid" = "u"."id"');

  // ================= GROUP BY / HAVING =================================
  check("groupBy + having compose",
        sql.select("t").count("*", "n").groupBy("cat").having("cat", ">", 1).toSql().sql ===
          'SELECT COUNT(*) AS "n" FROM t GROUP BY "cat" HAVING "cat" > ?');
  check("groupBy accepts a single string (not just an array)",
        sql.select("t").groupBy("a").toSql().sql === 'SELECT * FROM t GROUP BY "a"');
  var hr = sql.select("t").count("*", "n").groupBy("cat").havingRaw("COUNT(*) > ?", [5]).toSql();
  check("havingRaw guards + parenthesizes the raw HAVING fragment",
        hr.sql.indexOf("HAVING (COUNT(*) > ?)") !== -1 && hr.params.length === 1 && hr.params[0] === 5);

  // ================= ORDER BY / LIMIT / OFFSET =========================
  check("orderBy defaults to ASC",
        sql.select("t").orderBy("a").toSql().sql === 'SELECT * FROM t ORDER BY "a" ASC');
  rejects("orderBy rejects a non-asc/desc direction", function () {
    return sql.select("t").orderBy("a", "sideways");
  }, "sql-builder/bad-direction");
  check("offset emits OFFSET after LIMIT",
        sql.select("t").limit(10).offset(20).toSql().sql === "SELECT * FROM t LIMIT 10 OFFSET 20");
  check("limit(0) is a valid non-negative integer",
        sql.select("t").limit(0).toSql().sql === "SELECT * FROM t LIMIT 0");
  rejects("limit rejects a negative integer", function () { return sql.select("t").limit(-1); },
    "sql-builder/bad-limit");
  rejects("limit rejects a non-integer", function () { return sql.select("t").limit(1.5); },
    "sql-builder/bad-limit");
  rejects("offset rejects a negative integer", function () { return sql.select("t").offset(-1); },
    "sql-builder/bad-offset");

  // ================= LIKE modes / BETWEEN ==============================
  check("whereLike substring wraps live % around the escaped term",
        sql.select("t").whereLike("n", "a%b").toSql().params[0] === "%a~%b%");
  check("whereLike prefix keeps a trailing live %",
        sql.select("t").whereLike("n", "a%b", "prefix").toSql().params[0] === "a~%b%");
  check("whereLike exact escapes without adding a wildcard",
        sql.select("t").whereLike("n", "a%b", "exact").toSql().params[0] === "a~%b");
  check("orWhereLike joins with OR",
        sql.select("t").where("a", 1).orWhereLike("n", "x").toSql().sql.indexOf('OR "n" LIKE ?') !== -1);
  rejects("whereLike rejects an unknown mode", function () {
    return sql.select("t").whereLike("n", "x", "evil");
  }, "sql-builder/bad-like-mode");
  rejects("whereLike rejects a non-string term", function () {
    return sql.select("t").whereLike("n", 5);
  }, "sql-builder/bad-like-term");
  var bt = sql.select("t").whereBetween("age", 18, 65).toSql();
  check("whereBetween emits col BETWEEN ? AND ? binding both bounds",
        bt.sql.indexOf('"age" BETWEEN ? AND ?') !== -1 && bt.params.length === 2 &&
          bt.params[0] === 18 && bt.params[1] === 65);
  rejects("BETWEEN operator rejects a non-pair", function () {
    return sql.select("t").where("age", "BETWEEN", [1]).toSql();
  }, "sql-builder/bad-between");

  // ================= nested groups / EXISTS / scalar sub ===============
  check("whereGroup parenthesizes an AND/OR sub-group",
        sql.select("t").whereGroup(function (q) { q.where("a", 1).orWhere("b", 2); }).where("c", 3)
          .toSql().sql === 'SELECT * FROM t WHERE ("a" = ? OR "b" = ?) AND "c" = ?');
  check("orWhereGroup joins the group with OR",
        sql.select("t").where("a", 1).orWhereGroup(function (q) { q.where("b", 2); }).toSql().sql ===
          'SELECT * FROM t WHERE "a" = ? OR ("b" = ?)');
  check("an empty whereGroup contributes nothing (no dangling parens)",
        sql.select("t").where("a", 1).whereGroup(function () {}).toSql().sql ===
          'SELECT * FROM t WHERE "a" = ?');
  rejects("whereGroup requires a function", function () {
    return sql.select("t").whereGroup("nope");
  }, "sql-builder/bad-closure");
  check("whereExists composes a correlated EXISTS subquery",
        sql.select("u").whereExists(
          sql.select("o").columns(["id"]).whereRaw('"o"."uid" = "u"."id"')).toSql().sql ===
          'SELECT * FROM u WHERE EXISTS (SELECT "id" FROM o WHERE ("o"."uid" = "u"."id"))');
  check("whereNotExists emits NOT EXISTS",
        sql.select("u").whereNotExists(sql.select("o").columns(["id"])).toSql().sql ===
          'SELECT * FROM u WHERE NOT EXISTS (SELECT "id" FROM o)');
  rejects("whereExists rejects a non-builder", function () {
    return sql.select("u").whereExists("nope");
  }, "sql-builder/bad-subquery");
  check("whereSub composes a scalar-subquery comparison",
        sql.select("u").whereSub("cnt", ">", sql.select("o").count("*", "c")).toSql().sql ===
          'SELECT * FROM u WHERE "cnt" > (SELECT COUNT(*) AS "c" FROM o)');
  rejects("whereSub rejects an off-allowlist operator", function () {
    return sql.select("u").whereSub("cnt", "EVIL", sql.select("o"));
  }, "sql-builder/bad-operator");
  check("selectSub embeds an aliased scalar subquery in the projection",
        sql.select("u").columns(["id"]).selectSub(sql.select("o").count("*", "c"), "order_count")
          .toSql().sql === 'SELECT "id", (SELECT COUNT(*) AS "c" FROM o) AS "order_count" FROM u');
  rejects("selectSub rejects a non-builder", function () {
    return sql.select("u").selectSub("nope", "a");
  }, "sql-builder/bad-subquery");

  // ================= orWhereIn / whereNotIn ============================
  check("orWhereIn joins an IN list with OR",
        sql.select("t").where("a", 1).orWhereIn("b", [2, 3]).toSql().sql ===
          'SELECT * FROM t WHERE "a" = ? OR "b" IN (?, ?)');
  check("whereNotIn emits NOT IN",
        sql.select("t").whereNotIn("id", [1, 2]).toSql().sql ===
          'SELECT * FROM t WHERE "id" NOT IN (?, ?)');

  // ================= CTE composition ===================================
  check("with(name, builder) prepends a quoted CTE clause",
        sql.select("main").with("cte", sql.select("src").columns(["id"])).columns(["id"]).toSql().sql ===
          'WITH "cte" AS (SELECT "id" FROM src) SELECT "id" FROM main');
  rejects("with rejects a non-builder/non-string body", function () {
    return sql.select("t").with("c", 42).toSql();
  }, "sql-builder/bad-cte");

  // ================= UPDATE setRaw + allowNoWhere ======================
  var srw = sql.update("t").setRaw("count", '"count" + ?', [1]).where("id", 1).toSql();
  check("setRaw quotes the column + guards the raw RHS",
        srw.sql === 'UPDATE t SET "count" = "count" + ? WHERE "id" = ?' &&
          srw.params.length === 2 && srw.params[0] === 1 && srw.params[1] === 1);
  check("update allowNoWhere() opts into a full-table write",
        sql.update("t").set({ a: 1 }).allowNoWhere().toSql().sql === 'UPDATE t SET "a" = ?');
  check("delete allowNoWhere() opts into a full-table delete",
        sql.delete("t").allowNoWhere().toSql().sql === "DELETE FROM t");

  // ================= column-membership gate modes ======================
  rejects("allowedColumns(reject) refuses an unknown projection column", function () {
    return sql.select("t").allowedColumns(["a"]).columns(["ghost"]).toSql();
  }, "sql-builder/unknown-column");
  check("columnGate('warn') permits an unknown column",
        sql.select("t").allowedColumns(["a"]).columnGate("warn").columns(["ghost"]).toSql().sql ===
          'SELECT "ghost" FROM t');
  check("columnGate('off') permits an unknown column",
        sql.select("t").allowedColumns(["a"]).columnGate("off").columns(["ghost"]).toSql().sql ===
          'SELECT "ghost" FROM t');
  rejects("columnGate rejects an unknown mode", function () {
    return sql.select("t").columnGate("evil");
  }, "sql-builder/bad-gate-mode");
  rejects("allowedColumns rejects an empty array", function () {
    return sql.select("t").allowedColumns([]);
  }, "sql-builder/bad-allowed-columns");
  rejects("allowedColumns opt at construction rejects a non-array", function () {
    return sql.select("t", { allowedColumns: "a" });
  }, "sql-builder/bad-allowed-columns");
  check("allowedColumns gate also fences orderBy",
        (function () {
          try { sql.select("t").allowedColumns(["a"]).columns(["a"]).orderBy("ghost").toSql(); return false; }
          catch (e) { return e.code === "sql-builder/unknown-column"; }
        })());

  // ================= alterTable branches ===============================
  check("alterTable dropColumn quotes the column",
        sql.alterTable("t", { dropColumn: "old" }, { dialect: "postgres" }).sql ===
          'ALTER TABLE t DROP COLUMN "old"');
  check("alterTable renameColumn quotes both names",
        sql.alterTable("t", { renameColumn: { from: "a", to: "b" } }, { dialect: "postgres" }).sql ===
          'ALTER TABLE t RENAME COLUMN "a" TO "b"');
  check("alterTable addColumn NOT NULL + DEFAULT",
        sql.alterTable("t", { addColumn: { name: "active", type: "boolean", notNull: true, default: false } },
          { dialect: "postgres" }).sql === 'ALTER TABLE t ADD COLUMN "active" BOOLEAN NOT NULL DEFAULT FALSE');
  rejects("alterTable with an empty change descriptor refused", function () {
    return sql.alterTable("t", {}, { dialect: "postgres" });
  }, "sql-builder/bad-alter");
  rejects("alterTable with no change descriptor refused", function () {
    return sql.alterTable("t", null);
  }, "sql-builder/bad-alter");
  rejects("alterTable renameColumn requires from + to", function () {
    return sql.alterTable("t", { renameColumn: { from: "a" } }, { dialect: "postgres" });
  }, "sql-builder/bad-alter");

  // ================= dropTable / createIndex option branches ===========
  check("dropTable ifExists:false drops the IF EXISTS clause",
        sql.dropTable("t", { ifExists: false, dialect: "postgres" }).sql === "DROP TABLE t");
  check("dropTable cascade is ignored on a non-postgres dialect",
        sql.dropTable("t", { cascade: true, dialect: "sqlite" }).sql === "DROP TABLE IF EXISTS t");
  check("dropTable cascade emits CASCADE on postgres",
        sql.dropTable("t", { cascade: true, dialect: "postgres" }).sql === "DROP TABLE IF EXISTS t CASCADE");
  check("createIndex unique + ifNotExists:false",
        sql.createIndex("i", "t", ["a"], { unique: true, ifNotExists: false, dialect: "postgres" }).sql ===
          'CREATE UNIQUE INDEX "i" ON t ("a")');
  rejects("createIndex rejects an empty columns array", function () {
    return sql.createIndex("i", "t", [], { dialect: "postgres" });
  }, "sql-builder/bad-columns");

  // ================= DDL DEFAULT rendering =============================
  check("string DEFAULT is single-quoted with the quote doubled",
        sql.createTable("t", [{ name: "s", type: "text", default: "x'y" }], { dialect: "postgres" }).sql ===
          'CREATE TABLE IF NOT EXISTS t ("s" TEXT DEFAULT \'x\'\'y\')');
  check("boolean DEFAULT renders TRUE/FALSE",
        sql.createTable("t", [{ name: "b", type: "boolean", default: true }], { dialect: "postgres" })
          .sql.indexOf("DEFAULT TRUE") !== -1);
  check("null DEFAULT renders NULL",
        sql.createTable("t", [{ name: "n", type: "int", default: null }], { dialect: "postgres" })
          .sql.indexOf("DEFAULT NULL") !== -1);
  check("numeric DEFAULT renders inline",
        sql.createTable("t", [{ name: "n", type: "int", default: 5 }], { dialect: "postgres" })
          .sql.indexOf("DEFAULT 5") !== -1);
  rejects("object DEFAULT refused", function () {
    return sql.createTable("t", [{ name: "n", type: "int", default: {} }], { dialect: "postgres" });
  }, "sql-builder/bad-default");
  // A hostile string DEFAULT cannot break out of the doubled-quote literal:
  // the whole thing stays one balanced single-statement (catalog output gate).
  check("hostile string DEFAULT stays inside one balanced literal",
        sql.createTable("t", [{ name: "s", type: "text", default: "'); DROP TABLE x; --" }],
          { dialect: "postgres" }).sql ===
          'CREATE TABLE IF NOT EXISTS t ("s" TEXT DEFAULT \'\'\'); DROP TABLE x; --\')');
  // A verbatim column type that tries to stack a statement is caught by the
  // quote-aware catalog output gate (defence-in-depth backstop).
  rejects("verbatim type that stacks a statement is refused", function () {
    return sql.createTable("t", [{ name: "c", type: "int); DROP TABLE x; --" }], { dialect: "postgres" });
  }, "sql-builder/stacked-statement");
  rejects("verbatim type with an unbalanced paren is refused", function () {
    return sql.createTable("t", [{ name: "c", type: "NUMERIC(10" }], { dialect: "postgres" });
  }, "sql-builder/unbalanced");
  check("verbatim (unrecognized) type is emitted as-is in type position",
        sql.createTable("t", [{ name: "c", type: "GEOGRAPHY" }], { dialect: "postgres" })
          .sql.indexOf('"c" GEOGRAPHY') !== -1);
  rejects("empty column type refused", function () {
    return sql.createTable("t", [{ name: "c", type: "" }], { dialect: "postgres" });
  }, "sql-builder/bad-type");
  check("createTable CHECK constraint rides the guarded raw path",
        sql.createTable("t", [{ name: "age", type: "int", constraints: 'CHECK ("age" >= 0)' }],
          { dialect: "postgres" }).sql === 'CREATE TABLE IF NOT EXISTS t ("age" BIGINT CHECK ("age" >= 0))');
  rejects("createTable constraint that smuggles a comment is refused", function () {
    return sql.createTable("t", [{ name: "age", type: "int", constraints: "CHECK (1=1)); DROP TABLE x; --" }],
      { dialect: "postgres" });
  }, "sql-builder/guard-refused");
  check("createTable ifNotExists:false drops IF NOT EXISTS",
        sql.createTable("t", [{ name: "a", type: "int" }], { dialect: "postgres", ifNotExists: false }).sql ===
          'CREATE TABLE t ("a" BIGINT)');
  rejects("createTable column that is not an object refused", function () {
    return sql.createTable("t", ["notanobject"], { dialect: "postgres" });
  }, "sql-builder/bad-column");

  // ================= table() reference shapes ==========================
  check("table('schema.table') quotes both segments",
        sql.table("public.users").toString("postgres") === '"public"."users"');
  check("table prefix is prepended then quoted as one identifier",
        sql.table("orders", { prefix: "shop_" }).toString("sqlite") === '"shop_orders"');
  check("table alias is appended for joins",
        sql.table("orders", { alias: "o" }).toString("postgres") === 'orders "o"');
  check("bare default table stays unquoted (clusterStorage rewrite target)",
        sql.table("audit_log").toString() === "audit_log");
  check("quoteName forces a bare default name to be quoted",
        sql.table("audit_log", { quoteName: true }).toString("postgres") === '"audit_log"');
  rejects("three-segment dotted table refused", function () { return sql.table("a.b.c"); },
    "sql-builder/bad-table");
  rejects("trailing-dot table refused", function () { return sql.table("a."); },
    "sql-builder/bad-table");
  rejects("empty table name refused", function () { return sql.table(""); },
    "sql-builder/bad-table");
  rejects("qualified column with three segments refused", function () {
    return sql.select("t").columns(["a.b.c"]).toSql();
  }, "sql-builder/bad-column");

  // ================= fn / cast boundary codes ==========================
  rejects("fn(NOW) is refused on sqlite (no portable form)", function () {
    return sql.insert("t", { dialect: "sqlite" }).values({ at: sql.fn("NOW") }).toSql();
  }, "sql-builder/fn-unsupported");
  rejects("fn rejects a non-string name", function () { return sql.fn(5); },
    "sql-builder/bad-fn");
  rejects("cast rejects a non-string type", function () { return sql.cast("x", 5); },
    "sql-builder/bad-cast");
  rejects("cast rejects an empty type", function () { return sql.cast("x", ""); },
    "sql-builder/bad-cast");

  // ================= casWon field coverage ============================
  check("casWon reads the raw-mysql rowsAffected field",
        sql.casWon({ rowsAffected: 1 }).won === true);
  check("casWon prioritizes rowCount over a raw driver field",
        sql.casWon({ rowCount: 1, changes: 5 }).won === true &&
          sql.casWon({ rowCount: 1, changes: 5 }).rowCount === 1);
  rejects("casWon treats a non-numeric row count as indeterminate", function () {
    return sql.casWon({ rowCount: "1" });
  }, "sql-builder/no-row-count");

  // ================= output-gate boundaries (string / count) ===========
  rejects("a bound string over the per-value ceiling is refused", function () {
    return sql.insert("t").values({ a: "x".repeat(64 * 1024 * 1024 + 1) }).toSql();
  }, "sql-builder/param-too-large");
  rejects("a statement over the bind-parameter wire ceiling is refused", function () {
    var big = [];
    for (var i = 0; i < 65536; i += 1) big.push(i);
    return sql.select("t").whereIn("id", big).toSql();
  }, "sql-builder/too-many-params");
  // A Date / bigint value binds cleanly (concrete-value param check passes).
  check("Date + bigint bind as concrete params",
        sql.insert("t").values({ at: new Date(0), n: 10n }).toSql().params.length === 2);

  // ================= multi-row INSERT ==================================
  var mr = sql.insert("t", { dialect: "postgres" })
    .values([{ a: 1, b: sql.fn("NOW") }, { a: 2, b: 3 }]).toSql();
  check("multi-row insert resolves each row's cells (fn per-row, no param)",
        mr.sql === 'INSERT INTO t ("a", "b") VALUES (?, NOW()), (?, ?)' &&
          mr.params.length === 3 && mr.params[0] === 1 && mr.params[1] === 2 && mr.params[2] === 3);
  rejects("multi-row insert with a heterogeneous key set refused (no silent drop)", function () {
    return sql.insert("t").values([{ a: 1, b: 2 }, { a: 3, c: 4 }]).toSql();
  }, "sql-builder/missing-column");

  // ================= upsert doUpdate / conflict paths ==================
  check("upsert doUpdate({col: rawExpr}) draws its ? from exprParams",
        sql.upsert("kv", { dialect: "postgres" }).columns(["k", "n"]).values({ k: "a", n: 1 })
          .onConflict(["k"]).doUpdate({ n: 'EXCLUDED."n" + ?' }, [10]).toSql().sql ===
          'INSERT INTO kv ("k", "n") VALUES (?, ?) ON CONFLICT ("k") DO UPDATE SET "n" = EXCLUDED."n" + ?');
  check("upsert doUpdate({col: '?'}) re-binds the column to a supplied param",
        sql.upsert("kv", { dialect: "postgres" }).columns(["k", "n"]).values({ k: "a", n: 1 })
          .onConflict(["k"]).doUpdate({ n: "?" }, [99]).toSql().params.join(",") === "a,1,99");
  check("upsert conflictWhere fences the DO UPDATE on postgres",
        sql.upsert("kv", { dialect: "postgres" }).columns(["k", "v"]).values({ k: "a", v: 5 })
          .onConflict(["k"]).doUpdateFromExcluded(["v"]).conflictWhere('kv."v" < ?', [5]).toSql().sql
          .indexOf('DO UPDATE SET "v" = EXCLUDED."v" WHERE kv."v" < ?') !== -1);
  check("upsert mysql doNothing no-ops a key column to itself",
        sql.upsert("kv", { dialect: "mysql" }).columns(["k", "v"]).values({ k: "a", v: 1 })
          .onConflict(["k"]).doNothing().toSql().sql ===
          "INSERT INTO kv (`k`, `v`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `k` = `k`");
  rejects("upsert without a conflict action refused", function () {
    return sql.upsert("kv").columns(["k"]).values({ k: "a" }).toSql();
  }, "sql-builder/conflict-action");
  rejects("upsert doUpdate without onConflict refused on postgres", function () {
    return sql.upsert("kv", { dialect: "postgres" }).values({ k: "a", v: 1 }).doUpdateFromExcluded(["v"]).toSql();
  }, "sql-builder/bad-conflict");
  rejects("upsert values() rejects a non-object row", function () {
    return sql.upsert("kv").columns(["k"]).values([1]);
  }, "sql-builder/bad-values");

  // ================= whereInArray dialect degrade + IS-non-null ========
  check("whereInArray degrades to an expanded IN list on mysql",
        sql.select("t", { dialect: "mysql" }).whereInArray("id", [1, 2, 3]).toSql().sql ===
          "SELECT * FROM t WHERE `id` IN (?, ?, ?)");

  // ================= createPolicy secondary branches ===================
  check("createPolicy RESTRICTIVE with no role + no withCheck",
        sql.createPolicy("p", "t", { permissive: false, using: "col = 1", allowLiterals: false },
          { dialect: "postgres" }).sql === 'CREATE POLICY "p" ON "t" AS RESTRICTIVE FOR ALL USING (col = 1)');
  rejects("createPolicy rejects an off-allowlist command", function () {
    return sql.createPolicy("p", "t", { command: "TRUNCATE", using: "x" }, { dialect: "postgres" });
  }, "sql-builder/bad-rls-command");

  // ================= createVirtualTable no-tokenize + FK pluralizer =====
  check("createVirtualTable without tokenize omits the tokenize clause",
        sql.createVirtualTable("fts", { columns: ["a", "b"] }).sql ===
          'CREATE VIRTUAL TABLE IF NOT EXISTS "fts" USING fts5("a", "b")');
  check("defineTable FK pluralizer: x-ending entity -> ...es (boxId -> boxes)",
        sql.defineTable("t", [{ name: "boxId", type: "int" }], { dialect: "postgres" })
          .statements[0].sql.indexOf("REFERENCES boxes") !== -1);
  check("defineTable FK pluralizer: s-ending entity -> ...es (classId -> classes)",
        sql.defineTable("t", [{ name: "classId", type: "int" }], { dialect: "postgres" })
          .statements[0].sql.indexOf("REFERENCES classes") !== -1);

  // ================= toExternalSql translates casts ($N + ::type) =======
  check("toExternalSql renumbers ? -> $N and preserves the ::type suffix",
        sql.insert("d", { dialect: "postgres" })
          .values({ id: 1, meta: sql.cast('{"a":1}', "jsonb") }).toExternalSql("postgres").sql ===
          'INSERT INTO d ("id", "meta") VALUES ($1, $2::jsonb)');
}

if (require.main === module) {
  Promise.resolve().then(run).then(function () {
    console.log("sql-coverage: OK — " + helpers.getChecks() + " checks passed");
    process.exit(0);
  }).catch(function (err) {
    console.error(err && err.stack ? err.stack : String(err));
    process.exit(1);
  });
}

module.exports = { run: run };
