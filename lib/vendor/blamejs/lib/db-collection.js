"use strict";
/**
 * @module     b.db.collection
 * @nav        Data
 * @title      Collection
 * @order      210
 * @card       Mongo-style facade over `b.db.from(name)`. Wraps the
 *             chainable Query builder in `{ insert, find, findOne,
 *             update, remove, count, paginate }` for codebases
 *             migrating from MongoDB or for primitives that prefer
 *             the document-store call shape.
 *
 * @intro
 *   `b.db.collection(name)` returns a small adapter that maps Mongo-
 *   shape calls onto the framework's query-builder primitives:
 *
 *     b.db.collection("users").findOne({ email: "alice@x.com" });
 *       → b.db.from("users").where({ email: "alice@x.com" }).first();
 *
 *     b.db.collection("users").update({ _id }, { $set: { name } });
 *       → b.db.from("users").where({ _id }).updateOne({ name });
 *
 *     b.db.collection("users").update({ _id }, { $inc: { failed: 1 } });
 *       → b.db.from("users").where({ _id }).increment("failed", 1);
 *
 *   Operators migrating from a Mongo-shaped codebase can drop in this
 *   facade without rewriting every call site to the chainable builder.
 *   New code typically reaches for the
 *   builder directly — `b.db.from(...)` is more expressive and
 *   doesn't pretend to be Mongo.
 *
 *   Supported update operators: `$set` (assign), `$inc` (atomic
 *   increment per column — composes `Query.increment`), `$unset`
 *   (set to NULL).
 */

var lazyRequire = require("./lazy-require");

// db.js → db-collection.js → db.from() would create a require cycle.
// Defer the lookup to call-time so the binding lands after both
// modules finish loading.
var db = lazyRequire(function () { return require("./db"); });

function _validateQueryShape(query) {
  if (!query || typeof query !== "object" || Array.isArray(query)) {
    throw new TypeError("collection: query must be a plain object");
  }
}

function _applyQuery(builder, query) {
  // Mongo-shape supports `field: value` for equality and `field:
  // { $gt: x }` / `{ $lt: x }` / `{ $gte: x }` / `{ $lte: x }` /
  // `{ $ne: x }` / `{ $in: [...] }` / `{ $like: "pattern" }` for
  // operators. Anything else throws — refuse silently translating
  // unknown operators into something that might match more rows
  // than intended.
  var keys = Object.keys(query);
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    var v = query[k];
    if (v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof Date)) {
      var opKeys = Object.keys(v);
      for (var j = 0; j < opKeys.length; j += 1) {
        var op = opKeys[j];
        var val = v[op];
        switch (op) {
          case "$eq":  builder.where(k, "=",  val); break;
          case "$ne":  builder.where(k, "!=", val); break;
          case "$gt":  builder.where(k, ">",  val); break;
          case "$gte": builder.where(k, ">=", val); break;
          case "$lt":  builder.where(k, "<",  val); break;
          case "$lte": builder.where(k, "<=", val); break;
          case "$in":
            if (!Array.isArray(val)) {
              throw new TypeError("collection: $in requires an array (got " + typeof val + ")");
            }
            builder.where(k, "IN", val);
            break;
          case "$like":
            if (typeof val !== "string") {
              throw new TypeError("collection: $like requires a string");
            }
            builder.where(k, "LIKE", val);
            break;
          default:
            throw new TypeError("collection: unsupported query operator '" + op +
              "' on field '" + k + "' (allowed: $eq / $ne / $gt / $gte / $lt / $lte / $in / $like)");
        }
      }
    } else {
      builder.where(k, "=", v);
    }
  }
}

function _splitUpdateOperators(update) {
  // Allow either Mongo-shape `{ $set: {...}, $inc: {...} }` OR plain
  // `{ field: value, ... }` (treated as $set). Returns a tuple of
  // sets / increments / unsets so the caller can dispatch.
  if (!update || typeof update !== "object" || Array.isArray(update)) {
    throw new TypeError("collection: update must be a plain object");
  }
  var keys = Object.keys(update);
  var hasOperator = keys.some(function (k) { return k.charAt(0) === "$"; });
  if (!hasOperator) {
    return { sets: update, incs: null, unsets: null };
  }
  var sets = null;
  var incs = null;
  var unsets = null;
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    if (k === "$set") {
      if (!update[k] || typeof update[k] !== "object") {
        throw new TypeError("collection: $set value must be an object");
      }
      sets = update[k];
    } else if (k === "$inc") {
      if (!update[k] || typeof update[k] !== "object") {
        throw new TypeError("collection: $inc value must be an object");
      }
      incs = update[k];
    } else if (k === "$unset") {
      if (!update[k] || typeof update[k] !== "object") {
        throw new TypeError("collection: $unset value must be an object");
      }
      unsets = update[k];
    } else {
      throw new TypeError("collection: unsupported update operator '" + k +
        "' (allowed: $set / $inc / $unset; or pass a plain object for an implicit $set)");
    }
  }
  return { sets: sets, incs: incs, unsets: unsets };
}

/**
 * @primitive b.db.collection
 * @signature b.db.collection(name)
 * @since     0.8.58
 * @status    stable
 * @related   b.db.from, b.db
 *
 * Returns a Mongo-style adapter for the named table. Each method
 * dispatches to `b.db.from(name)` under the hood; sealed-column
 * semantics, derived-hash translation, and audit emission carry
 * through unchanged.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [{
 *     name: "users",
 *     columns: { _id: "TEXT PRIMARY KEY", email: "TEXT", failed: "INTEGER NOT NULL DEFAULT 0" },
 *   }] });
 *   var users = b.db.collection("users");
 *   users.insert({ _id: "u1", email: "alice@x.com" });
 *   users.findOne({ email: "alice@x.com" });
 *   users.update({ _id: "u1" }, { $inc: { failed: 1 } });
 *   users.update({ _id: "u1" }, { $set: { failed: 0 } });
 *   users.remove({ _id: "u1" });
 */
function collection(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw new TypeError("collection(name): name must be a non-empty string");
  }
  return {
    name: name,

    // Insert one document. Returns the inserted row with `_id` filled
    // in (if absent on input). Composes Query.insertOne.
    insert: function (doc) {
      return db().from(name).insertOne(doc);
    },

    // Insert many. Returns array of inserted rows.
    insertMany: function (docs) {
      return db().from(name).insertMany(docs);
    },

    // Find rows matching the query. Returns an array. Pass `opts.limit`
    // / `opts.offset` / `opts.orderBy` / `opts.orderDir` for paging.
    find: function (query, opts) {
      _validateQueryShape(query || {});
      var q = db().from(name);
      _applyQuery(q, query || {});
      if (opts && opts.orderBy) q.orderBy(opts.orderBy, opts.orderDir || "asc");
      if (opts && opts.limit !== undefined) q.limit(opts.limit);
      if (opts && opts.offset !== undefined) q.offset(opts.offset);
      return q.all();
    },

    // Find one row, or null. Equivalent to `.find(...).all()[0]` but
    // emits `LIMIT 1` so the engine doesn't materialise the rest.
    findOne: function (query) {
      _validateQueryShape(query);
      var q = db().from(name);
      _applyQuery(q, query);
      return q.first() || null;
    },

    // Update rows matching the query. Accepts Mongo `{ $set, $inc,
    // $unset }` operator form OR a plain field-map (treated as $set).
    // Returns the number of rows changed.
    //
    // `$inc` composes Query.increment so the SQL is
    //   UPDATE table SET col = COALESCE(col, 0) + ? WHERE ...
    // — atomic across concurrent writers, no fetch/mutate/store race.
    update: function (query, update, opts) {
      _validateQueryShape(query || {});
      var split = _splitUpdateOperators(update);
      var single = !(opts && opts.many === true);
      var changed = 0;

      // $inc — apply increments per column. Each call shares the
      // where-clause but is its own UPDATE statement (one SQL per
      // bumped column). The where filter must be re-built per call
      // because Query is single-shot.
      if (split.incs) {
        var incCols = Object.keys(split.incs);
        for (var i = 0; i < incCols.length; i += 1) {
          var qInc = db().from(name);
          _applyQuery(qInc, query || {});
          var delta = split.incs[incCols[i]];
          if (typeof delta !== "number" || !Number.isInteger(delta)) {
            throw new TypeError("collection.update: $inc.'" + incCols[i] + "' must be an integer");
          }
          changed += qInc.increment(incCols[i], delta);
        }
      }

      // $set / plain-object form — single UPDATE with the merged
      // changes object.
      var setObj = null;
      if (split.sets) setObj = Object.assign({}, split.sets);
      if (split.unsets) {
        if (!setObj) setObj = {};
        Object.keys(split.unsets).forEach(function (k) { setObj[k] = null; });
      }
      if (setObj && Object.keys(setObj).length > 0) {
        var qSet = db().from(name);
        _applyQuery(qSet, query || {});
        if (single) {
          changed += (qSet.updateOne(setObj) ? 1 : 0);
        } else {
          changed += qSet.updateMany(setObj);
        }
      }

      return changed;
    },

    // Convenience — `updateMany(query, update)` shorthand for
    // `update(query, update, { many: true })`.
    updateMany: function (query, update) {
      return this.update(query, update, { many: true });
    },

    // Remove rows matching the query. Returns the number of rows
    // deleted. Default deletes ONE row; pass `{ many: true }` to
    // delete all matches (matches the framework's `deleteMany` rule
    // — no unconditional deletes).
    remove: function (query, opts) {
      _validateQueryShape(query || {});
      var q = db().from(name);
      _applyQuery(q, query || {});
      if (opts && opts.many === true) {
        return q.deleteMany();
      }
      return q.deleteOne() ? 1 : 0;
    },

    // Count rows matching the query.
    count: function (query) {
      _validateQueryShape(query || {});
      var q = db().from(name);
      _applyQuery(q, query || {});
      return q.count();
    },

    // Paginate — `{ items, total, limit, offset, page, totalPages }`.
    // Composes Query.paginate.
    paginate: function (query, opts) {
      _validateQueryShape(query || {});
      var q = db().from(name);
      _applyQuery(q, query || {});
      return q.paginate(opts || {});
    },
  };
}

module.exports = { collection: collection };
