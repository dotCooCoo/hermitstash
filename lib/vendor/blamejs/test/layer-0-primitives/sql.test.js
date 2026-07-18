// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.sql — quote-by-construction query builder (composes b.safeSql) +
 * its final output validator. Covers each verb across dialects, the
 * where-family checks inherited from the executing query builder
 * (operator allowlist, IN-expansion, JSONB injection guard +
 * jsonb_exists emission), and every _assertEmittable boundary code.
 * Also drives the ordinary builder surface: aggregates, DISTINCT, the
 * JOIN family, GROUP BY / HAVING, ORDER BY / LIMIT / OFFSET validation,
 * the LIKE-mode + BETWEEN + nested-group + EXISTS / scalar-subquery
 * where helpers, CTE composition, setRaw, the column-membership gate
 * modes, the alterTable / dropTable / createIndex option branches, DDL
 * DEFAULT rendering, table-reference shapes, and the fn / cast / casWon
 * / output-gate boundary codes.
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

async function runBuilderSurface() {
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

  // ================= casWon field variants ============================
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
  check("b.sql.guardedUpdate", typeof b.sql.guardedUpdate === "function");
  check("b.sql.casWon",      typeof b.sql.casWon === "function");
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

  // ==== guardedUpdate (compare-and-swap UPDATE, #344) ====
  // The conditional-UPDATE sibling of insertSelectWhere: advance a status /
  // version ONLY when the row is still in the expected value, so two racing
  // transitions on an autocommit-only substrate cannot both win.

  // Canonical CAS: identity where() + a guardWhere() fence ANDed into one WHERE,
  // params bound set -> identity -> guard in order.
  var cas = sql.guardedUpdate("orders")
    .set({ status: "shipped" }).where("id", 7).guardWhere("status", "paid").toSql();
  check("guardedUpdate emits UPDATE...SET...WHERE id AND guard",
        cas.sql === 'UPDATE orders SET "status" = ? WHERE "id" = ? AND "status" = ?' &&
          cas.params.length === 3 && cas.params[0] === "shipped" &&
          cas.params[1] === 7 && cas.params[2] === "paid");

  // guardWhereOp for a non-equality fence (optimistic version / balance debit).
  var casOp = sql.guardedUpdate("wallets")
    .set({ balance: 90 }).where("id", 1).guardWhereOp("balance", ">=", 10).toSql();
  check("guardedUpdate guardWhereOp renders a >= fence",
        casOp.sql.indexOf('"balance" >= ?') !== -1 && casOp.params[casOp.params.length - 1] === 10);

  // A null-valued fence becomes IS NULL (col = NULL never matches), no null param.
  var casNull = sql.guardedUpdate("orders")
    .set({ locked_by: "node-a" }).where("id", 1).guardWhere("locked_by", null).toSql();
  check("guardedUpdate null fence renders IS NULL, binds no null",
        casNull.sql.indexOf('"locked_by" IS NULL') !== -1 && casNull.params.indexOf(null) === -1);

  // An UNDEFINED fence is refused (not silently collapsed to IS NULL) — an
  // omitted/unset expected value would turn a CAS into "match NULL-state rows"
  // and update the wrong rows. Only an EXPLICIT null means IS NULL.
  rejects("guardedUpdate guardWhere(undefined) is refused", function () {
    return sql.guardedUpdate("orders").set({ status: "x" }).where("id", 1)
      .guardWhere("status", undefined).toSql();
  }, "sql-builder/bad-guard-value");

  // mysql backtick quoting + postgres $N positional carry through unchanged.
  var casMy = sql.guardedUpdate("orders", { dialect: "mysql" })
    .set({ status: "shipped" }).where("id", 7).guardWhere("status", "paid").toSql();
  check("guardedUpdate mysql backtick quoting",
        casMy.sql === "UPDATE orders SET `status` = ? WHERE `id` = ? AND `status` = ?");
  var casPg = sql.guardedUpdate("orders", { dialect: "postgres" })
    .set({ status: "shipped" }).where("id", 7).guardWhere("status", "paid").toExternalSql("postgres");
  check("guardedUpdate toExternalSql postgres $N",
        casPg.sql.indexOf("$1") !== -1 && casPg.sql.indexOf("$3") !== -1 && casPg.sql.indexOf("?") === -1);

  // Refuses to render without a fence — an unguarded guardedUpdate is just a
  // plain update and almost always a CAS-forgotten bug.
  rejects("guardedUpdate without a guardWhere throws", function () {
    return sql.guardedUpdate("orders").set({ status: "x" }).where("id", 1).toSql();
  }, "sql-builder/no-guard");
  // set() is still required.
  rejects("guardedUpdate without set throws", function () {
    return sql.guardedUpdate("orders").where("id", 1).guardWhere("status", "paid").toSql();
  }, "sql-builder/empty-set");

  // casWon: own the rowCount -> won/lost mapping + cross-adapter field names.
  check("casWon: rowCount=1 -> won",            sql.casWon({ rowCount: 1 }).won === true);
  check("casWon: rowCount=0 -> lost",           sql.casWon({ rowCount: 0 }).won === false);
  check("casWon: rowCount=2 -> lost, count kept",
        sql.casWon({ rowCount: 2 }).won === false && sql.casWon({ rowCount: 2 }).rowCount === 2);
  check("casWon: raw sqlite changes field",     sql.casWon({ changes: 1 }).won === true);
  check("casWon: raw mysql affectedRows field", sql.casWon({ affectedRows: 1 }).won === true);
  rejects("casWon: indeterminate result throws (no phantom win)", function () {
    return sql.casWon({ foo: 1 });
  }, "sql-builder/no-row-count");
  rejects("casWon: non-object throws", function () {
    return sql.casWon(null);
  }, "sql-builder/bad-cas-result");

  // Real-engine execution: build the CAS with b.sql, run it against an actual
  // SQLite engine (node:sqlite), and prove the race contract end to end — the
  // first transition wins (rowCount 1, casWon true), a second racer on the now-
  // advanced row loses (rowCount 0, casWon false). This is the consumer path the
  // issue is about (cross-instance-safe transition on a single-statement
  // substrate); the same standard SQL runs identically on Postgres / MySQL.
  var nodeSqlite = null;
  try { nodeSqlite = require("node:sqlite"); } catch (_e) { nodeSqlite = null; }
  if (nodeSqlite && typeof nodeSqlite.DatabaseSync === "function") {
    var edb = new nodeSqlite.DatabaseSync(":memory:");
    edb.exec("CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT)");
    edb.prepare("INSERT INTO orders (id, status) VALUES (?, ?)").run(7, "paid");
    var casQ = sql.guardedUpdate("orders")
      .set({ status: "shipped" }).where("id", 7).guardWhere("status", "paid").toSql();
    var wonStmt = edb.prepare(casQ.sql);
    var won = wonStmt.run.apply(wonStmt, casQ.params);
    check("guardedUpdate live: winner casWon true (rowCount 1)", sql.casWon(won).won === true);
    var lostStmt = edb.prepare(casQ.sql);
    var lost = lostStmt.run.apply(lostStmt, casQ.params);
    check("guardedUpdate live: loser casWon false (rowCount 0)",
          sql.casWon(lost).won === false && sql.casWon(lost).rowCount === 0);
    check("guardedUpdate live: row advanced exactly once",
          edb.prepare("SELECT status FROM orders WHERE id = 7").get().status === "shipped");
    edb.close();
  }

  // ==== ordinary builder surface (aggregates, joins, grouping, DDL option branches) ====
  await runBuilderSurface();

  // ==== error / adversarial / defensive / option-default branch coverage ====
  runDialectTypeAndErrorBranches();
  runJsonbAndWhereFamilyBranches();
  runRawFragmentAndEmitBranches();
  runColumnGateCteAndProjectionBranches();
  runInsertUpdateDeleteBranches();
  runUpsertBranches();
  runDdlBranches();
  runRlsCatalogPragmaDefineBranches();
}

// The framework's dialect / logical-type normalizers reject an off-allowlist
// dialect at the config-time entry point, map every logical DDL type token to
// its dialect-final form, and refuse a non-identifier in identifier position.
function runDialectTypeAndErrorBranches() {
  var sql = b.sql;

  // Off-allowlist dialect throws at the entry point (every verb / DDL routes
  // through _normDialect).
  rejects("select on an unknown dialect refused", function () {
    return sql.select("t", { dialect: "oracle" });
  }, "sql-builder/bad-dialect");
  rejects("createTable on an unknown dialect refused", function () {
    return sql.createTable("t", [{ name: "a", type: "int" }], { dialect: "db2" });
  }, "sql-builder/bad-dialect");

  // The SqlBuilderError public constructor defaults its code when none is
  // supplied (the fallback that keeps `.code` always present).
  check("SqlBuilderError defaults its code",
        new sql.SqlBuilderError("boom").code === "sql-builder/invalid");
  check("SqlBuilderError keeps an explicit code",
        new sql.SqlBuilderError("boom", "sql-builder/custom").code === "sql-builder/custom");

  // Logical DDL types map to their dialect-final tokens - the binary / real /
  // numeric / timestamp / json families across the three dialects.
  check("blob -> BYTEA on postgres",
        sql.createTable("t", [{ name: "d", type: "blob" }], { dialect: "postgres" }).sql ===
          'CREATE TABLE IF NOT EXISTS t ("d" BYTEA)');
  check("blob -> LONGBLOB on mysql",
        sql.createTable("t", [{ name: "d", type: "blob" }], { dialect: "mysql" }).sql ===
          "CREATE TABLE IF NOT EXISTS t (`d` LONGBLOB)");
  check("bytea alias -> BLOB on sqlite",
        sql.createTable("t", [{ name: "d", type: "bytea" }]).sql ===
          'CREATE TABLE IF NOT EXISTS t ("d" BLOB)');
  check("binary alias -> LONGBLOB on mysql",
        sql.createTable("t", [{ name: "d", type: "binary" }], { dialect: "mysql" }).sql ===
          "CREATE TABLE IF NOT EXISTS t (`d` LONGBLOB)");
  check("float -> REAL",
        sql.createTable("t", [{ name: "d", type: "float" }]).sql.indexOf('"d" REAL') !== -1);
  check("decimal -> NUMERIC",
        sql.createTable("t", [{ name: "d", type: "decimal" }]).sql.indexOf('"d" NUMERIC') !== -1);
  check("timestamp -> TIMESTAMP",
        sql.createTable("t", [{ name: "d", type: "timestamp" }]).sql.indexOf('"d" TIMESTAMP') !== -1);
  check("json -> JSON on mysql",
        sql.createTable("t", [{ name: "d", type: "json" }], { dialect: "mysql" }).sql.indexOf("`d` JSON") !== -1);

  // A non-string / empty column name is refused in identifier position - both
  // the list-validated path (columns) and the expression path (orderBy).
  rejects("columns([<non-string>]) refused (identifier validate)", function () {
    return sql.insert("t").columns([5]);
  }, "sql-builder/bad-column");
  rejects("orderBy(<non-string>) refused (qualified-column validate)", function () {
    return sql.select("t").orderBy(123);
  }, "sql-builder/bad-column");
}

// The JSONB operator family + the where-helper set: containment / key-existence
// shape checks (Postgres-only), the FTS MATCH operator through _cmp, the OR
// object / 3-arg forms, and the array / json_each / between membership helpers.
function runJsonbAndWhereFamilyBranches() {
  var sql = b.sql;
  var pg = function () { return sql.select("t", { dialect: "postgres" }); };

  // @> containment: a JSON-string operand is parsed + validated; an object
  // operand is walked then canonically stringified; a non-JSON string refuses.
  check("where @> with an object operand binds canonical JSON",
        JSON.stringify(pg().where("meta", "@>", { a: 1 }).toSql().params) === '["{\\"a\\":1}"]');
  check("where @> with a JSON-string operand binds it",
        pg().where("meta", "@>", '{"a":1}').toSql().sql === 'SELECT * FROM t WHERE "meta" @> ?');
  rejects("where @> with an invalid JSON string refused", function () {
    return pg().where("meta", "@>", "not json").toSql();
  }, "sql-builder/bad-jsonb-value");

  // Key-existence operators: `?` needs a string key; `?|`/`?&` need a non-empty
  // array; they emit the jsonb_exists* function family (placeholder-safe).
  rejects("where '?' with a non-string key refused", function () {
    return pg().where("meta", "?", 123).toSql();
  }, "sql-builder/bad-jsonb-key");
  rejects("where '?|' with a non-array refused", function () {
    return pg().where("meta", "?|", "x").toSql();
  }, "sql-builder/bad-jsonb-keys");
  rejects("where '?&' with an empty array refused", function () {
    return pg().where("meta", "?&", []).toSql();
  }, "sql-builder/bad-jsonb-keys");
  check("where '?&' emits jsonb_exists_all binding the key array",
        pg().where("meta", "?&", ["a", "b"]).toSql().sql ===
          'SELECT * FROM t WHERE jsonb_exists_all("meta", ?)');
  check("where '?' emits jsonb_exists binding the single key",
        pg().where("meta", "?", "k").toSql().sql ===
          'SELECT * FROM t WHERE jsonb_exists("meta", ?)');

  // The FTS MATCH operator through the generic whereOp path: non-sqlite refuses,
  // an empty query string refuses, a valid one binds.
  rejects("whereOp(col, 'MATCH', ...) on postgres refused", function () {
    return pg().whereOp("c", "MATCH", "x").toSql();
  }, "sql-builder/match-sqlite-only");
  rejects("whereOp(col, 'MATCH', '') refused (empty query)", function () {
    return sql.select("t").whereOp("c", "MATCH", "").toSql();
  }, "sql-builder/bad-match");
  check("whereMatch binds the FTS query as one placeholder",
        sql.select("t").whereMatch("fts", "hello").toSql().sql ===
          'SELECT * FROM t WHERE "fts" MATCH ?');
  check("whereOp(col, 'MATCH', term) on sqlite binds the query",
        sql.select("t").whereOp("fts", "MATCH", "hello").toSql().sql ===
          'SELECT * FROM t WHERE "fts" MATCH ?');
  check("orWhereMatch OR-joins an FTS MATCH on sqlite",
        sql.select("t").where("a", 1).orWhereMatch("fts", "x").toSql().sql ===
          'SELECT * FROM t WHERE "a" = ? OR "fts" MATCH ?');
  rejects("orWhereMatch on a non-sqlite dialect refused", function () {
    return sql.select("t", { dialect: "postgres" }).orWhereMatch("fts", "x");
  }, "sql-builder/match-sqlite-only");
  rejects("orWhereMatch with an empty query refused", function () {
    return sql.select("t").orWhereMatch("fts", "");
  }, "sql-builder/bad-match");

  // orWhere object-form fans out to OR-joined equalities; orWhere 3-arg keeps
  // the operator.
  check("orWhere({obj}) OR-joins each key equality",
        sql.select("t").where("a", 1).orWhere({ b: 2, c: 3 }).toSql().sql ===
          'SELECT * FROM t WHERE "a" = ? OR "b" = ? OR "c" = ?');
  check("orWhere(field, op, value) keeps the operator",
        sql.select("t").where("a", 1).orWhere("b", ">", 2).toSql().sql ===
          'SELECT * FROM t WHERE "a" = ? OR "b" > ?');

  // Array / json_each / between membership helpers.
  check("whereBetween emits a BETWEEN pair",
        sql.select("t").whereBetween("age", 18, 65).toSql().sql ===
          'SELECT * FROM t WHERE "age" BETWEEN ? AND ?');
  check("whereInArray on postgres binds the whole array to = ANY(?)",
        sql.select("t", { dialect: "postgres" }).whereInArray("id", [1, 2, 3]).toSql().sql ===
          'SELECT * FROM t WHERE "id" = ANY(?)');
  rejects("whereInArray with an undefined element refused", function () {
    return sql.select("t").whereInArray("id", [1, undefined]);
  }, "sql-builder/bad-in-value");
  check("whereInJsonEach unrolls a JSON-array string via json_each",
        sql.select("t").whereInJsonEach("id", "[1,2,3]").toSql().sql ===
          'SELECT * FROM t WHERE "id" IN (SELECT value FROM json_each(?))');
  rejects("whereInJsonEach with a non-string refused", function () {
    return sql.select("t").whereInJsonEach("id", 5);
  }, "sql-builder/bad-json-each");
  rejects("whereSub with a non-builder subquery refused", function () {
    return sql.select("t").whereSub("c", "=", 5);
  }, "sql-builder/bad-subquery");
  rejects("whereLike with an unknown mode refused", function () {
    return sql.select("t").whereLike("n", "x", "weird");
  }, "sql-builder/bad-like-mode");

  // `col != NULL` / `col <> NULL` are UNKNOWN in SQL - refused like `= NULL`.
  rejects("where(col, '!=', null) refused (never true in SQL)", function () {
    return sql.select("t").where("a", "!=", null);
  }, "sql-builder/null-equality");
  rejects("where(col, '<>', null) refused (never true in SQL)", function () {
    return sql.select("t").where("a", "<>", null);
  }, "sql-builder/null-equality");
}

// The raw-fragment guard's shape / parity checks and the final output gate's
// param-shape refusals + the positional-translation terminal.
function runRawFragmentAndEmitBranches() {
  var sql = b.sql;

  rejects("whereRaw with a non-string sql refused", function () {
    return sql.select("t").whereRaw(123, []);
  }, "sql-builder/bad-raw");
  rejects("whereRaw with an empty sql refused", function () {
    return sql.select("t").whereRaw("");
  }, "sql-builder/bad-raw");
  check("whereRaw coerces a scalar param into a one-element bind list",
        JSON.stringify(sql.select("t").whereRaw("c = ?", 5).toSql().params) === "[5]");
  check("whereRaw with no params + zero placeholders binds nothing",
        sql.select("t").whereRaw('"a" IS NOT NULL').toSql().params.length === 0);
  rejects("whereRaw placeholder/param count mismatch refused", function () {
    return sql.select("t").whereRaw("c = ?", []).toSql();
  }, "sql-builder/placeholder-mismatch");
  // A raw fragment carrying a double-quoted identifier exercises the
  // quote-skipping pass of the raw JSONB-key-operator scanner - including a
  // doubled-quote escape inside the identifier.
  check("whereRaw passes a double-quoted identifier fragment through",
        sql.select("t").whereRaw('"c" = ?', [1]).toSql().sql ===
          'SELECT * FROM t WHERE ("c" = ?)');
  check("whereRaw skips a doubled-quote escape inside a quoted identifier",
        sql.select("t").whereRaw('"a""b" = ?', [1]).toSql().sql ===
          'SELECT * FROM t WHERE ("a""b" = ?)');

  // The output gate refuses a param that is not a concrete bindable value.
  rejects("binding a function value refused at the output gate", function () {
    return sql.insert("t").values({ a: function () {} }).toSql();
  }, "sql-builder/bad-param-value");
  rejects("binding a symbol value refused at the output gate", function () {
    return sql.insert("t").values({ a: Symbol("x") }).toSql();
  }, "sql-builder/bad-param-value");

  // toExternalSql: the free-function form on a builder + the chainable form
  // defaulting to the builder's own dialect both translate ? -> $N on postgres.
  check("toExternalSql(builder, 'postgres') translates ? -> $N",
        sql.toExternalSql(sql.select("t", { dialect: "postgres" }).where("a", 1), "postgres").sql ===
          'SELECT * FROM t WHERE "a" = $1');
  check("builder.toExternalSql() defaults to the builder's dialect",
        sql.select("t", { dialect: "postgres" }).where("a", 1).toExternalSql().sql ===
          'SELECT * FROM t WHERE "a" = $1');
  rejects("toExternalSql on a non-builder / non-result refused", function () {
    return sql.toExternalSql(42, "postgres");
  }, "sql-builder/bad-external-input");
}

// The column-membership gate (opt + chainable + warn/reject/qualified), the WITH
// (CTE) composition (raw body + recursive), and the SELECT projection helpers.
function runColumnGateCteAndProjectionBranches() {
  var sql = b.sql;

  rejects("allowedColumns opt must be a non-empty array", function () {
    return sql.select("t", { allowedColumns: [] });
  }, "sql-builder/bad-allowed-columns");
  rejects("allowedColumns() chainable form rejects an empty array", function () {
    return sql.select("t").allowedColumns([]);
  }, "sql-builder/bad-allowed-columns");
  check("columnGate 'warn' admits an unknown column",
        sql.select("t", { allowedColumns: ["a"], columnGateMode: "warn" })
          .columns(["a", "zzz"]).toSql().sql === 'SELECT "a", "zzz" FROM t');
  rejects("columnGate 'reject' (default with a set) refuses an unknown column", function () {
    return sql.select("t", { allowedColumns: ["a"] }).where("secret", 1).toSql();
  }, "sql-builder/unknown-column");
  check("column gate matches on the bare segment of a qualified column",
        sql.select("t", { allowedColumns: ["a"] }).where("x.a", 1).toSql().sql ===
          'SELECT * FROM t WHERE "x"."a" = ?');
  rejects("columnGate mode must be reject | warn | off", function () {
    return sql.select("t").columnGate("bogus");
  }, "sql-builder/bad-gate-mode");

  // A raw CTE body rides the same guarded-fragment path; a recursive CTE marks
  // the WITH clause RECURSIVE and concatenates the sub's params first.
  check("with(name, rawFragment, params) composes a guarded raw CTE",
        sql.select("main").with("c", '"a" > ?', [1]).columns(["x"]).toSql().sql ===
          'WITH "c" AS ("a" > ?) SELECT "x" FROM main');
  check("withRecursive marks RECURSIVE and folds the sub-builder params first",
        sql.select("tree").withRecursive("tree", sql.select("nodes").where("parent", 5)).toSql().sql ===
          'WITH RECURSIVE "tree" AS (SELECT * FROM nodes WHERE "parent" = ?) SELECT * FROM tree');
  check("with(name, rawFragment, params, { guardProfile }) honours the opt",
        sql.select("m").with("c", '"a" > ?', [1], { guardProfile: "strict" }).columns(["x"]).toSql().sql ===
          'WITH "c" AS ("a" > ?) SELECT "x" FROM m');
  rejects("with(name, <non-builder-non-string>) refused", function () {
    return sql.select("t").with("c", 5);
  }, "sql-builder/bad-cte");

  // Projection helpers: raw projection with a bound param, a raw join with a
  // bound param, a scalar subquery projection, and its non-builder refusal.
  check("selectRaw carries a bound param into the projection",
        JSON.stringify(sql.select("t").selectRaw("? + 1", [10]).toSql().params) === "[10]");
  check("joinRaw carries a bound param into the join",
        JSON.stringify(sql.select("t").joinRaw("INNER JOIN o ON o.x = ?", [3]).toSql().params) === "[3]");
  check("selectSub composes a scalar subquery projection",
        sql.select("t").selectSub(sql.select("o").count("*", "c"), "cnt").toSql().sql ===
          'SELECT (SELECT COUNT(*) AS "c" FROM o) AS "cnt" FROM t');
  rejects("selectSub with a non-builder refused", function () {
    return sql.select("t").selectSub(5, "x");
  }, "sql-builder/bad-subquery");
  rejects("select columns() with a non-array refused", function () {
    return sql.select("t").columns("x");
  }, "sql-builder/bad-columns");
  check("groupBy accepts an array of columns",
        sql.select("t").groupBy(["a", "b"]).toSql().sql === 'SELECT * FROM t GROUP BY "a", "b"');

  // Row-locking option branches (Postgres): FOR SHARE + SKIP LOCKED, FOR UPDATE
  // NOWAIT.
  check("forShare SKIP LOCKED emits on postgres",
        sql.select("t", { dialect: "postgres" }).where("a", 1).forShare({ skipLocked: true }).toSql().sql
          .indexOf("FOR SHARE SKIP LOCKED") !== -1);
  check("forUpdate NOWAIT emits on postgres",
        sql.select("t", { dialect: "postgres" }).where("a", 1).forUpdate({ noWait: true }).toSql().sql
          .indexOf("FOR UPDATE NOWAIT") !== -1);
}

// INSERT column / value shape checks, UPDATE set forms, DELETE allow-no-where,
// RETURNING normalization, and the INSERT...SELECT...WHERE conditional verb.
function runInsertUpdateDeleteBranches() {
  var sql = b.sql;

  // INSERT column / value shapes.
  rejects("insert columns() with a non-array refused", function () {
    return sql.insert("t").columns("x");
  }, "sql-builder/bad-columns");
  rejects("insert values(array) without a prior columns() refused", function () {
    return sql.insert("t").values([1, 2]);
  }, "sql-builder/no-columns");
  rejects("insert values(array) with a count mismatch refused", function () {
    return sql.insert("t").columns(["a", "b"]).values([1]);
  }, "sql-builder/value-count");
  check("insert values(array) aligned to columns() emits one row",
        sql.insert("t").columns(["a", "b"]).values([1, 2]).toSql().sql ===
          'INSERT INTO t ("a", "b") VALUES (?, ?)');
  rejects("insert values() with a non-object non-array refused", function () {
    return sql.insert("t").values(5);
  }, "sql-builder/bad-values");
  rejects("insert values({}) empty row refused", function () {
    return sql.insert("t").values({});
  }, "sql-builder/empty-values");
  rejects("insert row missing a declared column refused", function () {
    return sql.insert("t").columns(["a", "b"]).values({ a: 1 });
  }, "sql-builder/missing-column");
  rejects("insert row with an extra column refused (no silent drop)", function () {
    return sql.insert("t").columns(["a"]).values({ a: 1, z: 9 });
  }, "sql-builder/extra-column");
  rejects("insert render without any values() row refused", function () {
    return sql.insert("t").columns(["a"]).toSql();
  }, "sql-builder/empty-values");
  check("insert values([{},{}]) emits a multi-row tuple list",
        sql.insert("t").values([{ a: 1 }, { a: 2 }]).toSql().sql ===
          'INSERT INTO t ("a") VALUES (?), (?)');

  // RETURNING normalization: "*" default + array + the MySQL refusal.
  check("insert returning(array) quotes each column",
        sql.insert("t", { dialect: "postgres" }).values({ a: 1 }).returning(["a", "b"]).toSql().sql
          .indexOf('RETURNING "a", "b"') !== -1);
  check("insert returning('*') emits RETURNING *",
        sql.insert("t", { dialect: "postgres" }).values({ a: 1 }).returning("*").toSql().sql
          .indexOf("RETURNING *") !== -1);
  check("insert returning(<single string>) wraps the one column",
        sql.insert("t", { dialect: "postgres" }).values({ a: 1 }).returning("a").toSql().sql
          .indexOf('RETURNING "a"') !== -1);
  rejects("RETURNING on a MySQL delete refused", function () {
    return sql.delete("t", { dialect: "mysql" }).where("a", 1).returning(["a"]).toSql();
  }, "sql-builder/returning-unsupported");

  // UPDATE set forms.
  rejects("update set({}) empty object refused", function () {
    return sql.update("t").set({}).where("a", 1);
  }, "sql-builder/empty-set");
  check("update set(col, value) single-assignment form",
        sql.update("t").set("x", 5).where("a", 1).toSql().sql ===
          'UPDATE t SET "x" = ? WHERE "a" = ?');
  check("update setRaw composes a guarded raw assignment",
        sql.update("t").setRaw("n", '"n" + ?', [1]).where("a", 1).toSql().sql ===
          'UPDATE t SET "n" = "n" + ? WHERE "a" = ?');

  // DELETE deliberate unconditional opt-in.
  check("delete allowNoWhere() emits an unconditional DELETE",
        sql.delete("t").allowNoWhere().toSql().sql === "DELETE FROM t");

  // INSERT ... SELECT ... WHERE (the conditional append-only verb).
  rejects("insertSelectWhere columns() with a non-array refused", function () {
    return sql.insertSelectWhere("t").columns("x");
  }, "sql-builder/bad-columns");
  rejects("insertSelectWhere values(array) without columns() refused", function () {
    return sql.insertSelectWhere("t").values([1]);
  }, "sql-builder/no-columns");
  rejects("insertSelectWhere values(array) count mismatch refused", function () {
    return sql.insertSelectWhere("t").columns(["a", "b"]).values([1]);
  }, "sql-builder/value-count");
  check("insertSelectWhere values(array) + where emits a guarded conditional insert",
        sql.insertSelectWhere("t").columns(["a"]).values([1]).where("bal", ">", 0).toSql().sql ===
          'INSERT INTO t ("a") SELECT ? WHERE "bal" > ?');
  rejects("insertSelectWhere values({}) empty object refused", function () {
    return sql.insertSelectWhere("t").values({});
  }, "sql-builder/empty-values");
  rejects("insertSelectWhere row missing a column refused", function () {
    return sql.insertSelectWhere("t").columns(["a", "b"]).values({ a: 1 });
  }, "sql-builder/missing-column");
  rejects("insertSelectWhere row with an extra column refused", function () {
    return sql.insertSelectWhere("t").columns(["a"]).values({ a: 1, z: 2 });
  }, "sql-builder/extra-column");
  rejects("insertSelectWhere values() with a bad shape refused", function () {
    return sql.insertSelectWhere("t").values(5);
  }, "sql-builder/bad-values");
  check("insertSelectWhere object row + whereExists composes a balance fence",
        sql.insertSelectWhere("ledger").values({ amt: -5 })
          .whereExists(sql.select("ledger").selectRaw("1").whereRaw('"bal" >= ?', [5])).toSql().sql ===
          'INSERT INTO ledger ("amt") SELECT ? WHERE EXISTS (SELECT 1 FROM ledger WHERE ("bal" >= ?))');
  check("insertSelectWhere allowNoWhere() opts out of the guard requirement",
        sql.insertSelectWhere("t").values({ a: 1 }).allowNoWhere().toSql().sql ===
          'INSERT INTO t ("a") SELECT ?');
  rejects("insertSelectWhere without a where() (and no opt-in) refused", function () {
    return sql.insertSelectWhere("t").values({ a: 1 }).toSql();
  }, "sql-builder/no-where");
}

// The UPSERT verb - the dialect-divergence centrepiece: standard (Postgres /
// SQLite) ON CONFLICT paths, the MySQL ON DUPLICATE KEY paths (including the
// guarded IF-eval-order form + the auto-emitted readback SELECT), and every
// conflict-action / value-shape refusal.
function runUpsertBranches() {
  var sql = b.sql;

  rejects("upsert columns() non-array refused", function () {
    return sql.upsert("t").columns("x");
  }, "sql-builder/bad-columns");
  rejects("upsert values() non-object refused", function () {
    return sql.upsert("t").values([1]);
  }, "sql-builder/bad-values");
  rejects("upsert values({}) empty refused", function () {
    return sql.upsert("t").values({});
  }, "sql-builder/empty-values");
  rejects("upsert row missing a column refused", function () {
    return sql.upsert("t").columns(["a", "b"]).values({ a: 1 });
  }, "sql-builder/missing-column");
  rejects("upsert row with an extra column refused", function () {
    return sql.upsert("t").columns(["a"]).values({ a: 1, z: 2 });
  }, "sql-builder/extra-column");
  rejects("upsert onConflict([]) empty refused", function () {
    return sql.upsert("t").onConflict([]);
  }, "sql-builder/bad-conflict");
  rejects("upsert doUpdateFromExcluded([]) empty refused", function () {
    return sql.upsert("t").doUpdateFromExcluded([]);
  }, "sql-builder/conflict-action");
  rejects("upsert doUpdate(<scalar>) refused", function () {
    return sql.upsert("t").doUpdate(5);
  }, "sql-builder/conflict-action");
  rejects("upsert doUpdate({}) empty map refused", function () {
    return sql.upsert("t").doUpdate({});
  }, "sql-builder/conflict-action");
  rejects("upsert render without values() refused", function () {
    return sql.upsert("t").doNothing().toSql();
  }, "sql-builder/empty-values");
  rejects("upsert render without a conflict action refused", function () {
    return sql.upsert("t").values({ id: 1 }).toSql();
  }, "sql-builder/conflict-action");
  rejects("upsert doUpdate without onConflict on postgres refused", function () {
    return sql.upsert("t", { dialect: "postgres" }).values({ id: 1, n: 2 })
      .doUpdateFromExcluded(["n"]).toSql();
  }, "sql-builder/bad-conflict");

  // Standard (Postgres / SQLite) conflict actions.
  var pgU = function () { return sql.upsert("t", { dialect: "postgres" }); };
  check("upsert DO UPDATE SET col = EXCLUDED.col",
        pgU().values({ id: 1, n: 2 }).onConflict(["id"]).doUpdateFromExcluded(["n"]).toSql().sql ===
          'INSERT INTO t ("id", "n") VALUES (?, ?) ON CONFLICT ("id") DO UPDATE SET "n" = EXCLUDED."n"');
  check("upsert onConflict(<single string>) wraps to a one-key target",
        pgU().values({ id: 1, n: 2 }).onConflict("id").doUpdateFromExcluded(["n"]).toSql().sql
          .indexOf('ON CONFLICT ("id")') !== -1);
  check("upsert doUpdate(<array>) delegates to doUpdateFromExcluded",
        pgU().values({ id: 1, n: 2 }).onConflict(["id"]).doUpdate(["n"]).toSql().sql ===
          'INSERT INTO t ("id", "n") VALUES (?, ?) ON CONFLICT ("id") DO UPDATE SET "n" = EXCLUDED."n"');
  check("upsert doUpdate scalar exprParams is coerced to a one-element list",
        JSON.stringify(pgU().values({ id: 1, n: 2 }).onConflict(["id"]).doUpdate({ n: "?" }, 7)
          .toSql().params) === "[1,2,7]");
  check("upsert DO NOTHING without an onConflict target emits a bare ON CONFLICT",
        pgU().values({ id: 1 }).doNothing().toSql().sql ===
          'INSERT INTO t ("id") VALUES (?) ON CONFLICT DO NOTHING');
  check("upsert doUpdate({col:'?'}) re-binds a supplied param",
        JSON.stringify(pgU().values({ id: 1, n: 2 }).onConflict(["id"]).doUpdate({ n: "?" }, [9])
          .toSql().params) === "[1,2,9]");
  check("upsert doUpdate({col:rawExpr}) composes a guarded raw assignment",
        pgU().values({ id: 1, n: 2 }).onConflict(["id"]).doUpdate({ n: 'EXCLUDED."n" + ?' }, [1])
          .toSql().sql.indexOf('DO UPDATE SET "n" = EXCLUDED."n" + ?') !== -1);
  rejects("upsert doUpdate expr that is neither '?' nor a string refused (standard)", function () {
    return pgU().values({ id: 1, n: 2 }).onConflict(["id"]).doUpdate({ n: 5 }).toSql();
  }, "sql-builder/conflict-action");
  check("upsert DO NOTHING on postgres",
        pgU().values({ id: 1 }).onConflict(["id"]).doNothing().toSql().sql ===
          'INSERT INTO t ("id") VALUES (?) ON CONFLICT ("id") DO NOTHING');
  check("upsert conflictWhere fences the DO UPDATE",
        pgU().values({ id: 1, n: 2 }).onConflict(["id"]).doUpdateFromExcluded(["n"])
          .conflictWhere('EXCLUDED."n" > "t"."n"', []).toSql().sql
          .indexOf('WHERE EXCLUDED."n" > "t"."n"') !== -1);

  // MySQL ON DUPLICATE KEY paths.
  var myU = function () { return sql.upsert("t", { dialect: "mysql" }); };
  check("upsert MySQL DO NOTHING no-ops a key column",
        myU().values({ id: 1, n: 2 }).onConflict(["id"]).doNothing().toSql().sql ===
          "INSERT INTO t (`id`, `n`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `id` = `id`");
  check("upsert MySQL update-from-excluded emits VALUES(col)",
        myU().values({ id: 1, n: 2 }).doUpdateFromExcluded(["n"]).toSql().sql
          .indexOf("ON DUPLICATE KEY UPDATE `n` = VALUES(`n`)") !== -1);
  check("upsert MySQL doUpdate({col:'?'}) re-binds",
        myU().values({ id: 1, n: 2 }).doUpdate({ n: "?" }, [7]).toSql().sql
          .indexOf("ON DUPLICATE KEY UPDATE `n` = ?") !== -1);
  check("upsert MySQL doUpdate({col:rawExpr}) composes a guarded raw assignment",
        myU().values({ id: 1, n: 2 }).doUpdate({ n: '"n" + ?' }, [1]).toSql().sql
          .indexOf('ON DUPLICATE KEY UPDATE `n` = "n" + ?') !== -1);
  rejects("upsert MySQL doUpdate expr that is neither '?' nor a string refused", function () {
    return myU().values({ id: 1, n: 2 }).doUpdate({ n: 5 }).toSql();
  }, "sql-builder/conflict-action");
  check("upsert MySQL readback without an onConflict key falls back to the first column",
        myU().values({ id: 1, n: 2 }).doUpdateFromExcluded(["n"]).returning(["id"]).toSql()
          .readbackSql.sql === "SELECT `id` FROM t WHERE `id` = ?");
  rejects("upsert MySQL readback with a conflict key outside the value set refused", function () {
    return myU().columns(["a", "b"]).values({ a: 1, b: 2 }).onConflict(["c"])
      .doUpdateFromExcluded(["b"]).returning(["a"]).toSql();
  }, "sql-builder/bad-conflict");
  check("upsert MySQL guarded conflictWhere wraps each SET in IF(...) and orders the guard column last",
        myU().values({ id: 1, ver: 2, n: 3 }).doUpdate({ n: "?", ver: "?" }, [3, 2])
          .conflictWhere('"ver" < ?', [2], { guardColumn: "ver" }).toSql().sql
          .indexOf("`n` = IF(") !== -1);
  check("upsert MySQL guarded conflictWhere with the guard column declared first still orders it last",
        myU().values({ id: 1, ver: 2, n: 3 }).doUpdate({ ver: "?", n: "?" }, [2, 3])
          .conflictWhere('"ver" < ?', [2], { guardColumn: "ver" }).toSql().sql
          .indexOf('`n` = IF("ver" < ?, ?, `n`), `ver` = IF(') !== -1);
  check("upsert MySQL guarded conflictWhere without a guardColumn keeps declared order",
        myU().values({ id: 1, n: 3 }).doUpdate({ n: "?" }, [3])
          .conflictWhere('"n" < ?', [3]).toSql().sql.indexOf('`n` = IF("n" < ?, ?, `n`)') !== -1);
  check("upsert MySQL DO NOTHING without an onConflict no-ops the first column",
        myU().values({ id: 1, n: 2 }).doNothing().toSql().sql ===
          "INSERT INTO t (`id`, `n`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `id` = `id`");
  check("upsert MySQL returning() auto-emits a keyed readback SELECT",
        myU().values({ id: 1, n: 2 }).onConflict(["id"]).doUpdateFromExcluded(["n"]).returning(["id", "n"])
          .toSql().readbackSql.sql === "SELECT `id`, `n` FROM t WHERE `id` = ?");
  rejects("upsert MySQL readback on a server-function conflict key refused", function () {
    return myU().values({ id: sql.fn("CURRENT_TIMESTAMP"), n: 2 }).onConflict(["id"])
      .doUpdateFromExcluded(["n"]).returning("*").toSql();
  }, "sql-builder/bad-conflict");
}

// DDL builders - createTable (auto-increment / references / composite PK /
// defaults / verbatim constraints), createIndex, alterTable, dropTable, and the
// sqlite FTS5 virtual-table builder.
function runDdlBranches() {
  var sql = b.sql;

  rejects("createTable with a non-array columns refused", function () {
    return sql.createTable("t", "x");
  }, "sql-builder/bad-columns");
  rejects("createTable with a non-object column spec refused", function () {
    return sql.createTable("t", ["x"]);
  }, "sql-builder/bad-column");
  check("createTable autoIncrement -> BIGSERIAL on postgres",
        sql.createTable("t", [{ name: "id", autoIncrement: true }], { dialect: "postgres" }).sql ===
          'CREATE TABLE IF NOT EXISTS t ("id" BIGSERIAL PRIMARY KEY)');
  check("createTable serial -> AUTO_INCREMENT on mysql",
        sql.createTable("t", [{ name: "id", serial: true }], { dialect: "mysql" }).sql ===
          "CREATE TABLE IF NOT EXISTS t (`id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY)");
  rejects("createTable autoIncrement + default is contradictory", function () {
    return sql.createTable("t", [{ name: "id", autoIncrement: true, default: 1 }]);
  }, "sql-builder/bad-column");
  check("createTable autoIncrement + verbatim constraints appends the guarded fragment",
        sql.createTable("t", [{ name: "id", autoIncrement: true, constraints: "CHECK (id > 0)" }]).sql
          .indexOf("INTEGER PRIMARY KEY AUTOINCREMENT CHECK (id > 0)") !== -1);
  check("createTable column notNull + unique + default compose",
        sql.createTable("t", [{ name: "e", type: "text", notNull: true, unique: true, default: "x" }]).sql ===
          'CREATE TABLE IF NOT EXISTS t ("e" TEXT NOT NULL UNIQUE DEFAULT \'x\')');
  check("createTable references (string) defaults to (id)",
        sql.createTable("t", [{ name: "uid", type: "int", references: "users" }]).sql
          .indexOf('REFERENCES users ("id")') !== -1);
  check("createTable references object with ON DELETE / ON UPDATE actions",
        sql.createTable("t", [{ name: "uid", type: "int",
          references: { table: "users", column: "id", onDelete: "CASCADE", onUpdate: "RESTRICT" } }]).sql
          .indexOf("ON DELETE CASCADE ON UPDATE RESTRICT") !== -1);
  rejects("createTable references without a table refused", function () {
    return sql.createTable("t", [{ name: "uid", type: "int", references: {} }]);
  }, "sql-builder/bad-references");
  rejects("createTable references with an empty table name refused", function () {
    return sql.createTable("t", [{ name: "uid", type: "int", references: { table: "" } }]);
  }, "sql-builder/bad-references");
  rejects("createTable references with a falsy non-false spec refused", function () {
    return sql.createTable("t", [{ name: "uid", type: "int", references: 0 }]);
  }, "sql-builder/bad-references");
  rejects("createTable references with an off-allowlist FK action refused", function () {
    return sql.createTable("t", [{ name: "uid", type: "int",
      references: { table: "users", onDelete: "EXPLODE" } }]);
  }, "sql-builder/bad-fk-action");
  check("createTable composite opts.primaryKey emits a table-level PK",
        sql.createTable("t", [{ name: "a", type: "int" }, { name: "b", type: "int" }],
          { primaryKey: ["a", "b"] }).sql.indexOf('PRIMARY KEY ("a", "b")') !== -1);
  rejects("createTable column PK + composite PK is refused (double PRIMARY KEY)", function () {
    return sql.createTable("t", [{ name: "a", type: "int", primaryKey: true }], { primaryKey: ["a"] });
  }, "sql-builder/bad-column");
  rejects("createTable column default of an unsupported type refused", function () {
    return sql.createTable("t", [{ name: "a", type: "int", default: {} }]);
  }, "sql-builder/bad-default");
  check("createTable ifNotExists:false drops the IF NOT EXISTS",
        sql.createTable("t", [{ name: "a", type: "int" }], { ifNotExists: false }).sql ===
          'CREATE TABLE t ("a" INTEGER)');

  // createIndex option branches.
  rejects("createIndex with a non-array columns refused", function () {
    return sql.createIndex("i", "t", []);
  }, "sql-builder/bad-columns");
  rejects("createIndex partial (where) on mysql refused", function () {
    return sql.createIndex("i", "t", ["a"], { dialect: "mysql", where: "a = 1" });
  }, "sql-builder/partial-index-unsupported");
  check("createIndex partial where + whereParams on postgres",
        sql.createIndex("i", "t", ["a"], { dialect: "postgres", where: '"a" > ?', whereParams: [1],
          allowLiterals: false }).sql.indexOf('WHERE "a" > ?') !== -1);
  check("createIndex unique + ifNotExists:false",
        sql.createIndex("i", "t", ["a"], { unique: true, ifNotExists: false }).sql ===
          'CREATE UNIQUE INDEX "i" ON t ("a")');

  // alterTable change descriptors.
  rejects("alterTable without a change descriptor refused", function () {
    return sql.alterTable("t", null);
  }, "sql-builder/bad-alter");
  rejects("alterTable addColumn without a name refused", function () {
    return sql.alterTable("t", { addColumn: { type: "int" } });
  }, "sql-builder/bad-column");
  check("alterTable addColumn with notNull / unique / default",
        sql.alterTable("t", { addColumn: { name: "c", type: "int", notNull: true, unique: true, default: 3 } })
          .sql === 'ALTER TABLE t ADD COLUMN "c" INTEGER NOT NULL UNIQUE DEFAULT 3');
  check("alterTable dropColumn quotes the column",
        sql.alterTable("t", { dropColumn: "c" }).sql === 'ALTER TABLE t DROP COLUMN "c"');
  check("alterTable renameColumn quotes both names",
        sql.alterTable("t", { renameColumn: { from: "a", to: "b" } }).sql ===
          'ALTER TABLE t RENAME COLUMN "a" TO "b"');
  rejects("alterTable renameColumn without both from/to refused", function () {
    return sql.alterTable("t", { renameColumn: { from: "a" } });
  }, "sql-builder/bad-alter");
  rejects("alterTable with an unknown change refused", function () {
    return sql.alterTable("t", { foo: 1 });
  }, "sql-builder/bad-alter");

  // dropTable option branches.
  check("dropTable cascade on postgres",
        sql.dropTable("t", { dialect: "postgres", cascade: true }).sql === "DROP TABLE IF EXISTS t CASCADE");
  check("dropTable cascade is ignored on a non-postgres dialect",
        sql.dropTable("t", { cascade: true }).sql === "DROP TABLE IF EXISTS t");
  check("dropTable ifExists:false drops the IF EXISTS",
        sql.dropTable("t", { ifExists: false }).sql === "DROP TABLE t");
  check("dropTable with no opts defaults to sqlite + IF EXISTS",
        sql.dropTable("t").sql === "DROP TABLE IF EXISTS t");

  rejects("createVirtualTable with no opts refused (no columns)", function () {
    return sql.createVirtualTable("f");
  }, "sql-builder/bad-columns");

  // sqlite FTS5 virtual table.
  rejects("createVirtualTable on a non-sqlite dialect refused", function () {
    return sql.createVirtualTable("f", { dialect: "postgres", columns: ["a"] });
  }, "sql-builder/vtable-sqlite-only");
  rejects("createVirtualTable with an empty columns array refused", function () {
    return sql.createVirtualTable("f", { columns: [] });
  }, "sql-builder/bad-columns");
  check("createVirtualTable emits UNINDEXED + an allowlisted tokenize clause",
        sql.createVirtualTable("f", { columns: [{ name: "id", unindexed: true }, "body"],
          tokenize: "unicode61 remove_diacritics 2" }).sql ===
          'CREATE VIRTUAL TABLE IF NOT EXISTS "f" USING fts5("id" UNINDEXED, "body", ' +
          "tokenize = 'unicode61 remove_diacritics 2')");
  rejects("createVirtualTable with an unsupported per-column option refused", function () {
    return sql.createVirtualTable("f", { columns: [{ name: "id", weird: 1 }] });
  }, "sql-builder/bad-vtable-column");
  rejects("createVirtualTable with a non-built-in tokenizer refused", function () {
    return sql.createVirtualTable("f", { columns: ["a"], tokenize: "customtok" });
  }, "sql-builder/bad-tokenize");
  rejects("createVirtualTable with an off-allowlist tokenize argument refused", function () {
    return sql.createVirtualTable("f", { columns: ["a"], tokenize: "porter zzz" });
  }, "sql-builder/bad-tokenize");
  rejects("createVirtualTable with a non-string tokenize refused", function () {
    return sql.createVirtualTable("f", { columns: ["a"], tokenize: 5 });
  }, "sql-builder/bad-tokenize");
  check("createVirtualTable ifNotExists:false drops the IF NOT EXISTS",
        sql.createVirtualTable("f", { columns: ["a"], ifNotExists: false }).sql ===
          'CREATE VIRTUAL TABLE "f" USING fts5("a")');
  check("createVirtualTable accepts a plain { name } column object (no UNINDEXED)",
        sql.createVirtualTable("f", { columns: [{ name: "body" }] }).sql ===
          'CREATE VIRTUAL TABLE IF NOT EXISTS "f" USING fts5("body")');
}

// Postgres RLS builders, the audited sqlite catalog / PRAGMA sub-API, and the
// defineTable schema-optimizer's option branches.
function runRlsCatalogPragmaDefineBranches() {
  var sql = b.sql;

  // Row-Level Security (Postgres-only; every builder refuses a non-pg dialect).
  rejects("enableRowLevelSecurity on sqlite refused", function () {
    return sql.enableRowLevelSecurity("t", { dialect: "sqlite" });
  }, "sql-builder/rls-postgres-only");
  check("enableRowLevelSecurity force emits FORCE",
        sql.enableRowLevelSecurity("sessions", { force: true }).sql ===
          'ALTER TABLE "sessions" FORCE ROW LEVEL SECURITY');
  check("enableRowLevelSecurity default emits ENABLE",
        sql.enableRowLevelSecurity("sessions").sql ===
          'ALTER TABLE "sessions" ENABLE ROW LEVEL SECURITY');
  check("disableRowLevelSecurity quotes a schema-qualified table",
        sql.disableRowLevelSecurity("sessions", { schema: "public" }).sql ===
          'ALTER TABLE "public"."sessions" DISABLE ROW LEVEL SECURITY');
  check("disableRowLevelSecurity with no opts defaults to postgres",
        sql.disableRowLevelSecurity("s").sql === 'ALTER TABLE "s" DISABLE ROW LEVEL SECURITY');
  rejects("disableRowLevelSecurity on mysql refused", function () {
    return sql.disableRowLevelSecurity("t", { dialect: "mysql" });
  }, "sql-builder/rls-postgres-only");
  rejects("createPolicy with no spec refused (no using predicate)", function () {
    return sql.createPolicy("p", "t");
  }, "sql-builder/bad-rls-predicate");
  check("dropPolicy with no opts defaults to postgres + IF EXISTS",
        sql.dropPolicy("p", "s").sql === 'DROP POLICY IF EXISTS "p" ON "s"');
  rejects("createPolicy on sqlite refused", function () {
    return sql.createPolicy("p", "t", { using: "x" }, { dialect: "sqlite" });
  }, "sql-builder/rls-postgres-only");
  rejects("createPolicy with an off-allowlist command refused", function () {
    return sql.createPolicy("p", "t", { command: "TRUNCATE", using: "1=1" });
  }, "sql-builder/bad-rls-command");
  rejects("createPolicy without a using predicate refused", function () {
    return sql.createPolicy("p", "t", {});
  }, "sql-builder/bad-rls-predicate");
  check("createPolicy composes the full clause order (RESTRICTIVE / role / USING / WITH CHECK)",
        sql.createPolicy("iso", "sessions", { role: "app_user", command: "SELECT", permissive: false,
          using: '"tenant_id" = ?', usingParams: [1], withCheck: '"tenant_id" = ?', withCheckParams: [1] },
          { schema: "public" }).sql ===
          'CREATE POLICY "iso" ON "public"."sessions" AS RESTRICTIVE FOR SELECT TO "app_user" ' +
          'USING ("tenant_id" = ?) WITH CHECK ("tenant_id" = ?)');
  check("dropPolicy IF EXISTS by default",
        sql.dropPolicy("iso", "sessions", { schema: "public" }).sql ===
          'DROP POLICY IF EXISTS "iso" ON "public"."sessions"');
  check("dropPolicy ifExists:false drops the IF EXISTS",
        sql.dropPolicy("iso", "sessions", { ifExists: false }).sql ===
          'DROP POLICY "iso" ON "sessions"');
  rejects("dropPolicy on mysql refused", function () {
    return sql.dropPolicy("p", "t", { dialect: "mysql" });
  }, "sql-builder/rls-postgres-only");

  // Catalog sub-API.
  check("catalog.listTables emits the sqlite_master scan",
        sql.catalog.listTables().sql ===
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'");
  check("catalog.tableExists binds the name as a parameter",
        JSON.stringify(sql.catalog.tableExists("audit").params) === '["audit"]');
  rejects("catalog.tableExists with an empty name refused", function () {
    return sql.catalog.tableExists("");
  }, "sql-builder/bad-table");
  check("catalog.tableInfo quotes the table into the PRAGMA",
        sql.catalog.tableInfo("audit").sql === 'PRAGMA table_info("audit")');
  rejects("catalog.tableInfo with a non-string name refused", function () {
    return sql.catalog.tableInfo(5);
  }, "sql-builder/bad-table");
  check("catalog.changes emits the changes() probe",
        sql.catalog.changes().sql === "SELECT changes() AS c");
  check("catalog.sampleRandom with a column list binds the limit",
        sql.catalog.sampleRandom("s", ["a", "b"], { limit: 5 }).sql ===
          'SELECT "a", "b" FROM "s" ORDER BY RANDOM() LIMIT ?');
  check("catalog.sampleRandom without columns projects *",
        sql.catalog.sampleRandom("s", null, { limit: 5 }).sql ===
          'SELECT * FROM "s" ORDER BY RANDOM() LIMIT ?');
  rejects("catalog.sampleRandom with an empty columns array refused", function () {
    return sql.catalog.sampleRandom("s", [], { limit: 5 });
  }, "sql-builder/bad-columns");
  rejects("catalog.sampleRandom with a non-positive limit refused", function () {
    return sql.catalog.sampleRandom("s", null, { limit: 0 });
  }, "sql-builder/bad-limit");
  rejects("catalog.sampleRandom with no opts refused (limit required)", function () {
    return sql.catalog.sampleRandom("s");
  }, "sql-builder/bad-limit");

  // PRAGMA sub-API (narrow allowlist).
  rejects("pragma with an off-allowlist verb refused", function () {
    return sql.pragma("foo");
  }, "sql-builder/bad-pragma");
  rejects("pragma('table_info') routes callers to catalog.tableInfo", function () {
    return sql.pragma("table_info");
  }, "sql-builder/bad-pragma");
  check("pragma wal_checkpoint defaults to PASSIVE",
        sql.pragma("wal_checkpoint").sql === "PRAGMA wal_checkpoint(PASSIVE)");
  check("pragma wal_checkpoint with an allowlisted mode",
        sql.pragma("wal_checkpoint", "TRUNCATE").sql === "PRAGMA wal_checkpoint(TRUNCATE)");
  rejects("pragma wal_checkpoint with an off-allowlist mode refused", function () {
    return sql.pragma("wal_checkpoint", "NOPE");
  }, "sql-builder/bad-pragma-arg");
  check("pragma journal_mode read (no arg)",
        sql.pragma("journal_mode").sql === "PRAGMA journal_mode");
  check("pragma journal_mode set with an allowlisted token",
        sql.pragma("journal_mode", "WAL").sql === "PRAGMA journal_mode=WAL");
  check("pragma synchronous set with an allowlisted level",
        sql.pragma("synchronous", "NORMAL").sql === "PRAGMA synchronous=NORMAL");
  rejects("pragma journal_mode with an off-vocabulary arg refused", function () {
    return sql.pragma("journal_mode", "BOGUS");
  }, "sql-builder/bad-pragma-arg");

  // defineTable schema optimizer.
  rejects("defineTable with an empty spec refused", function () {
    return sql.defineTable("t", []);
  }, "sql-builder/bad-columns");
  rejects("defineTable with a non-object column refused", function () {
    return sql.defineTable("t", ["x"]);
  }, "sql-builder/bad-column");
  check("defineTable auto-PK/FK/index yields CREATE TABLE + two indexes",
        sql.defineTable("orders", [{ name: "userId", type: "int" }, { name: "email", type: "text",
          index: true }], { dialect: "postgres" }).statements.length === 3);
  check("defineTable with a composite opts.primaryKey suppresses the auto identity PK",
        sql.defineTable("t", [{ name: "a", type: "int" }, { name: "b", type: "int" }],
          { primaryKey: ["a", "b"] }).statements.length === 1);
  check("defineTable references:false opts a column out of FK inference",
        sql.defineTable("t", [{ name: "userId", type: "int", references: false }]).statements.length === 1);
  check("defineTable explicit opts.indexes honored with autoIndex off",
        sql.defineTable("t", [{ name: "a", type: "int" }],
          { autoIndex: false, indexes: [{ columns: ["a"], unique: true, name: "myidx" }] })
          .statements.length === 2);
  rejects("defineTable index entry without a columns array refused", function () {
    return sql.defineTable("t", [{ name: "a", type: "int" }], { indexes: [{ columns: [] }] });
  }, "sql-builder/bad-index");
  rejects("defineTable index referencing an undeclared column refused", function () {
    return sql.defineTable("t", [{ name: "a", type: "int" }], { indexes: [{ columns: ["zzz"] }] });
  }, "sql-builder/unknown-column");
  check("defineTable with default opts (no opts arg) builds a single statement",
        sql.defineTable("solo", [{ name: "x", type: "int" }]).statements.length === 1);
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
