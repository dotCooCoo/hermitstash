// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   `b.db.collection(name, opts?)` returns a small adapter that maps
 *   Mongo-shape calls onto the framework's query-builder primitives:
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
 *   Schemaless-document support — three opts compose to give a
 *   document-store-shaped collection on top of the relational
 *   schema:
 *
 *     b.db.collection("users", {
 *       overflow:     "data",                          // unknown fields fold into this JSON-text column
 *       jsonColumns:  ["roles", "metadata"],           // listed columns auto-parsed on read, stringified on write
 *       sealedFields: { email: "emailHash" },          // registers cryptoField derivedHash so where({email}) rewrites
 *     });
 *
 *   Supported update operators: `$set` (assign — overflow-aware),
 *   `$inc` (atomic increment per real column — composes
 *   `Query.increment`; refused on overflow fields), `$unset` (set to
 *   NULL on real columns; remove the key from the overflow JSON).
 *
 *   Query operators: `$eq` / `$ne` / `$gt` / `$gte` / `$lt` / `$lte` /
 *   `$in` / `$like`. Overflow fields support `$eq` / `$ne` / `$in`
 *   only — range / LIKE require a real column with an index.
 */

var lazyRequire  = require("./lazy-require");
var safeJson     = require("./safe-json");
var validateOpts = require("./validate-opts");

// db.js → db-collection.js → db.from() would create a require cycle.
// Defer the lookup to call-time so the binding lands after both
// modules finish loading.
var db = lazyRequire(function () { return require("./db"); });

// cryptoField is loaded eagerly at top — no cycle (cryptoField does
// not require db-collection).
var cryptoField = require("./crypto-field");

function _validateQueryShape(query) {
  if (!query || typeof query !== "object" || Array.isArray(query)) {
    throw new TypeError("collection: query must be a plain object");
  }
}

function _validateConstructorOpts(opts, name) {
  if (opts.overflow !== undefined && opts.overflow !== null) {
    validateOpts.requireNonEmptyString(opts.overflow,
      "collection(" + name + "): opts.overflow",
      TypeError, "db-collection/bad-overflow");
  }
  validateOpts.optionalNonEmptyStringArray(opts.jsonColumns,
    "collection(" + name + "): opts.jsonColumns",
    TypeError, "db-collection/bad-json-columns");
  validateOpts.optionalNonEmptyStringArray(opts.columns,
    "collection(" + name + "): opts.columns",
    TypeError, "db-collection/bad-columns");
  validateOpts.optionalPlainObject(opts.sealedFields,
    "collection(" + name + "): opts.sealedFields",
    TypeError, "db-collection/bad-sealed-fields",
    "must be a { plain: hashColumn } map");
  if (opts.sealedFields !== undefined && opts.sealedFields !== null) {
    Object.keys(opts.sealedFields).forEach(function (plain) {
      if (typeof opts.sealedFields[plain] !== "string" || opts.sealedFields[plain].length === 0) {
        throw new TypeError("collection(" + name + "): sealedFields['" + plain + "'] must be a hash-column name");
      }
    });
  }
}

// Merge sealedFields declarations into the cryptoField registry so the
// existing query-rewrite path in db-query.js (`_isSealedField` →
// `cryptoField.lookupHash`) picks them up. Idempotent — re-declaring
// the same mapping is a no-op; declaring a new mapping for an existing
// table extends the existing record without dropping prior fields.
function _registerSealedFields(table, sealedFields) {
  var existing = cryptoField.getSchema(table) || {
    sealedFields: [],
    derivedHashes: {},
    hashNamespaces: {},
  };
  var nextSealed   = existing.sealedFields.slice();
  var nextDerived  = Object.assign({}, existing.derivedHashes);
  Object.keys(sealedFields).forEach(function (plain) {
    var hashCol = sealedFields[plain];
    if (nextSealed.indexOf(plain) === -1) nextSealed.push(plain);
    if (!nextDerived[hashCol]) nextDerived[hashCol] = { from: plain };
  });
  cryptoField.registerTable(table, {
    sealedFields:   nextSealed,
    derivedHashes:  nextDerived,
    hashNamespaces: existing.hashNamespaces,
  });
}

function _splitUpdateOperators(update) {
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
 * @signature b.db.collection(name, opts?)
 * @since     0.8.58
 * @status    stable
 * @related   b.db.from, b.db
 *
 * Returns a Mongo-style adapter for the named table. Each method
 * dispatches to `b.db.from(name)` under the hood; sealed-column
 * semantics, derived-hash translation, and audit emission carry
 * through unchanged.
 *
 * Pass `opts` to enable schemaless-document features:
 *
 *   - `overflow: "data"` — unknown insert/update fields fold into the
 *     named JSON-text column. `find` / `findOne` parse that column
 *     and merge its keys back onto the row. WHERE on an unknown field
 *     rewrites to `JSON_EXTRACT(<overflow>, '$.field')` (`$eq` / `$ne`
 *     / `$in` only — range / LIKE require a real column with an
 *     index).
 *   - `jsonColumns: ["roles", "metadata"]` — listed columns are
 *     `JSON.stringify`'d on write and parsed via `b.safeJson` on read.
 *   - `sealedFields: { email: "emailHash" }` — co-locates a sealed-
 *     column / derived-hash declaration with the collection. The
 *     plaintext field is registered as sealed; the hash column is
 *     registered as a `derivedHashes[hashCol] = { from: plain }`
 *     mapping in `b.cryptoField`. Subsequent `where({ email: "x" })`
 *     calls automatically rewrite to `where({ emailHash: <hash> })`
 *     via the existing query-builder rewrite path.
 *   - `columns: ["_id", "email", ...]` — explicit column whitelist.
 *     If omitted, the framework introspects via `PRAGMA table_info`
 *     once at first use and caches.
 *
 * @opts
 *   {
 *     overflow?:     string,                       // JSON-text column for unknown fields (off when absent)
 *     jsonColumns?:  string[],                     // auto-stringify on write, auto-parse on read
 *     sealedFields?: { [plain: string]: string },  // plain column → hash column; registers via b.cryptoField
 *     columns?:      string[],                     // explicit column whitelist (defaults to PRAGMA introspection)
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [{
 *     name: "users",
 *     columns: {
 *       _id:       "TEXT PRIMARY KEY",
 *       email:     "TEXT",
 *       emailHash: "TEXT",
 *       roles:     "TEXT",
 *       data:      "TEXT",
 *     },
 *   }] });
 *   var users = b.db.collection("users", {
 *     overflow:     "data",
 *     jsonColumns:  ["roles"],
 *     sealedFields: { email: "emailHash" },
 *   });
 *   users.insert({ _id: "u1", email: "alice@x.com", roles: ["admin"], dept: "eng", joined: "2026-01-01" });
 *   //   → roles is JSON-stringified; dept + joined fold into data; email seals + emailHash derives
 *   users.findOne({ email: "alice@x.com" });
 *   //   → { _id: "u1", email: "alice@x.com", roles: ["admin"], dept: "eng", joined: "2026-01-01" }
 *   users.find({ dept: "eng" });
 *   //   → JSON_EXTRACT(data, '$.dept') = 'eng'
 */
function collection(name, opts) {
  validateOpts.requireNonEmptyString(name, "collection(name): name", TypeError, "db-collection/bad-name");
  opts = opts || {};
  validateOpts.optionalPlainObject(opts, "collection: opts", TypeError, "db-collection/bad-opts",
    "must be a plain object");
  _validateConstructorOpts(opts, name);

  var overflow      = opts.overflow ? String(opts.overflow) : null;
  var jsonCols      = Array.isArray(opts.jsonColumns) ? opts.jsonColumns.slice() : [];
  var sealedFields  = opts.sealedFields || null;
  var explicitCols  = Array.isArray(opts.columns) ? opts.columns.slice() : null;

  if (sealedFields) _registerSealedFields(name, sealedFields);

  var _columnsCache = null;
  function _columns() {
    if (_columnsCache) return _columnsCache;
    if (explicitCols) { _columnsCache = explicitCols.slice(); return _columnsCache; }
    // PRAGMA table_info doesn't accept positional binding; the table
    // name has already been validated by db.from() once a Query is
    // built. Validate again here for the introspection path: the
    // existing schemaless-overflow detection runs BEFORE any Query
    // construction, so a malformed name would otherwise reach
    // PRAGMA's identifier interpolation. Reuses the same allow-list
    // safe-sql identifier check the chainable builder uses.
    var safeSql = require("./safe-sql");                                                      // allow:inline-require — keep the safe-sql edge off the module-load hot path
    safeSql.validateIdentifier(name, { allowReserved: true });
    var rows;
    try { rows = db().prepare("PRAGMA table_info(\"" + name + "\")").all(); }
    catch (e) {
      throw new Error("collection(" + name + "): unable to introspect column list — " +
        "either pass `columns: [...]` explicitly OR call b.db.collection() AFTER " +
        "b.db.init() resolves. Underlying error: " + ((e && e.message) || String(e)));
    }
    if (!rows || rows.length === 0) {
      throw new Error("collection(" + name + "): table has no columns OR does not exist. " +
        "Pass `columns: [...]` explicitly to bypass introspection.");
    }
    _columnsCache = rows.map(function (r) { return r.name; });
    if (overflow && _columnsCache.indexOf(overflow) === -1) {
      throw new Error("collection(" + name + "): overflow column '" + overflow +
        "' not present on table — declare it in your schema as TEXT");
    }
    var missingJson = jsonCols.filter(function (c) { return _columnsCache.indexOf(c) === -1; });
    if (missingJson.length > 0) {
      throw new Error("collection(" + name + "): jsonColumns reference unknown columns " +
        JSON.stringify(missingJson));
    }
    return _columnsCache;
  }

  function _stringifyJsonCols(row) {
    if (jsonCols.length === 0) return row;
    // Force column-list resolution so jsonColumns referencing unknown
    // columns surface at first use rather than silently producing
    // bad SQL bindings later.
    _columns();
    var out = Object.assign({}, row);
    jsonCols.forEach(function (c) {
      if (out[c] !== undefined && out[c] !== null && typeof out[c] !== "string") {
        out[c] = JSON.stringify(out[c]);
      }
    });
    return out;
  }

  function _prepareWriteDoc(doc) {
    var writeDoc = Object.assign({}, doc);
    if (overflow) {
      var cols = _columns();
      var extras = {};
      var hasExtras = false;
      Object.keys(writeDoc).forEach(function (k) {
        if (cols.indexOf(k) === -1) {
          extras[k] = writeDoc[k];
          hasExtras = true;
          delete writeDoc[k];
        }
      });
      if (hasExtras) {
        var existing = null;
        if (typeof writeDoc[overflow] === "object" && writeDoc[overflow] !== null && !Array.isArray(writeDoc[overflow])) {
          existing = writeDoc[overflow];
        }
        writeDoc[overflow] = JSON.stringify(Object.assign({}, existing || {}, extras));
      } else if (writeDoc[overflow] !== undefined && writeDoc[overflow] !== null && typeof writeDoc[overflow] === "object") {
        writeDoc[overflow] = JSON.stringify(writeDoc[overflow]);
      }
    }
    return _stringifyJsonCols(writeDoc);
  }

  function _decodeRowFromStorage(row) {
    if (!row || typeof row !== "object") return row;
    var out = Object.assign({}, row);
    jsonCols.forEach(function (c) {
      if (typeof out[c] === "string" && out[c].length > 0) {
        try { out[c] = safeJson.parse(out[c]); }
        catch (_e) { /* leave as string when content isn't valid JSON */ }
      }
    });
    if (overflow && out[overflow] !== undefined && out[overflow] !== null) {
      var extra = null;
      if (typeof out[overflow] === "string" && out[overflow].length > 0) {
        try { extra = safeJson.parse(out[overflow]); } catch (_e) { extra = null; }
      } else if (typeof out[overflow] === "object" && !Array.isArray(out[overflow])) {
        extra = out[overflow];
      }
      if (extra && typeof extra === "object" && !Array.isArray(extra)) {
        delete out[overflow];
        Object.keys(extra).forEach(function (k) {
          if (out[k] === undefined) out[k] = extra[k];
        });
      }
    }
    return out;
  }

  function _isOverflowField(field) {
    if (!overflow) return false;
    return _columns().indexOf(field) === -1;
  }

  function _applyEqualityForKey(builder, k, v) {
    if (_isOverflowField(k)) {
      builder.whereRaw('JSON_EXTRACT("' + overflow + '", ?) = ?', ["$." + k, v]);
    } else {
      builder.where(k, "=", v);
    }
  }

  function _applyOverflowOperator(builder, k, op, val) {
    switch (op) {
      case "$eq":  builder.whereRaw('JSON_EXTRACT("' + overflow + '", ?) = ?',  ["$." + k, val]); break;
      case "$ne":  builder.whereRaw('JSON_EXTRACT("' + overflow + '", ?) != ?', ["$." + k, val]); break;
      case "$in":
        if (!Array.isArray(val) || val.length === 0) {
          throw new TypeError("collection: $in on overflow field '" + k + "' requires a non-empty array");
        }
        var placeholders = val.map(function () { return "?"; }).join(", ");
        var params = ["$." + k].concat(val);
        builder.whereRaw('JSON_EXTRACT("' + overflow + '", ?) IN (' + placeholders + ")", params);
        break;
      default:
        throw new TypeError("collection: overflow field '" + k + "' supports $eq / $ne / $in only " +
          "(got '" + op + "'). Range / $like / sealed-rewrite require a real column.");
    }
  }

  function _applyQuery(builder, query) {
    var keys = Object.keys(query);
    for (var i = 0; i < keys.length; i += 1) {
      var k = keys[i];
      var v = query[k];
      if (v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof Date)) {
        var opKeys = Object.keys(v);
        for (var j = 0; j < opKeys.length; j += 1) {
          var op = opKeys[j];
          var val = v[op];
          if (_isOverflowField(k)) {
            _applyOverflowOperator(builder, k, op, val);
            continue;
          }
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
        _applyEqualityForKey(builder, k, v);
      }
    }
  }

  return {
    name: name,

    insert: function (doc) {
      return db().from(name).insertOne(_prepareWriteDoc(doc));
    },

    insertMany: function (docs) {
      if (!Array.isArray(docs)) throw new TypeError("collection.insertMany: docs must be an array");
      var prepared = docs.map(_prepareWriteDoc);
      return db().from(name).insertMany(prepared);
    },

    find: function (query, opts) {
      _validateQueryShape(query || {});
      var q = db().from(name);
      _applyQuery(q, query || {});
      if (opts && opts.orderBy) q.orderBy(opts.orderBy, opts.orderDir || "asc");
      if (opts && opts.limit !== undefined) q.limit(opts.limit);
      if (opts && opts.offset !== undefined) q.offset(opts.offset);
      var rows = q.all();
      return rows.map(_decodeRowFromStorage);
    },

    findOne: function (query) {
      _validateQueryShape(query);
      var q = db().from(name);
      _applyQuery(q, query);
      var row = q.first();
      return row ? _decodeRowFromStorage(row) : null;
    },

    update: function (query, update, opts) {
      _validateQueryShape(query || {});
      var split = _splitUpdateOperators(update);
      var single = !(opts && opts.many === true);
      var changed = 0;

      if (split.incs) {
        var incCols = Object.keys(split.incs);
        for (var i = 0; i < incCols.length; i += 1) {
          if (_isOverflowField(incCols[i])) {
            throw new TypeError("collection.update: $inc on overflow field '" + incCols[i] +
              "' is not supported — overflow fields are stored as JSON text and can't atomically increment. " +
              "Move the field to a real INTEGER column.");
          }
          var qInc = db().from(name);
          _applyQuery(qInc, query || {});
          var delta = split.incs[incCols[i]];
          if (typeof delta !== "number" || !Number.isInteger(delta)) {
            throw new TypeError("collection.update: $inc.'" + incCols[i] + "' must be an integer");
          }
          changed += qInc.increment(incCols[i], delta);
        }
      }

      // Combine $set + $unset into one effective change set, partitioned
      // into real-column writes vs overflow-JSON writes. Real-column
      // writes go through a single UPDATE; overflow writes are
      // read-modify-write on the JSON column inside a transaction so
      // concurrent updates don't lose fields.
      var setObj = null;
      if (split.sets) setObj = Object.assign({}, split.sets);
      if (split.unsets) {
        if (!setObj) setObj = {};
        Object.keys(split.unsets).forEach(function (k) { setObj[k] = null; });
      }
      if (setObj && Object.keys(setObj).length > 0) {
        var realChanges = {};
        var overflowChanges = null;
        var overflowDeletes = null;
        Object.keys(setObj).forEach(function (k) {
          if (_isOverflowField(k)) {
            if (split.unsets && Object.prototype.hasOwnProperty.call(split.unsets, k)) {
              if (!overflowDeletes) overflowDeletes = [];
              overflowDeletes.push(k);
            } else {
              if (!overflowChanges) overflowChanges = {};
              overflowChanges[k] = setObj[k];
            }
          } else {
            realChanges[k] = setObj[k];
          }
        });

        if (overflowChanges || overflowDeletes) {
          // Read each matched row's overflow column, merge changes,
          // write back. Single-row default; many-row when opts.many.
          var qFetch = db().from(name);
          _applyQuery(qFetch, query || {});
          if (single) qFetch.limit(1);
          var rows = qFetch.all();
          for (var ri = 0; ri < rows.length; ri += 1) {
            var existing = {};
            if (rows[ri][overflow] !== undefined && rows[ri][overflow] !== null) {
              if (typeof rows[ri][overflow] === "string" && rows[ri][overflow].length > 0) {
                try { existing = safeJson.parse(rows[ri][overflow]) || {}; } catch (_e) { existing = {}; }
              } else if (typeof rows[ri][overflow] === "object") {
                existing = rows[ri][overflow] || {};
              }
            }
            var nextOverflow = Object.assign({}, existing);
            if (overflowChanges) {
              Object.keys(overflowChanges).forEach(function (k) { nextOverflow[k] = overflowChanges[k]; });
            }
            if (overflowDeletes) {
              overflowDeletes.forEach(function (k) { delete nextOverflow[k]; });
            }
            // The row's identity: pick a primary-key-shaped column if
            // present, otherwise round-trip the full WHERE clause +
            // overflow column update. Most tables have an _id.
            var pkCol = "_id";
            if (rows[ri][pkCol] === undefined) {
              throw new Error("collection.update: overflow-field write requires an _id column on row " +
                "(got: " + JSON.stringify(Object.keys(rows[ri])) + "). Add _id to the schema.");
            }
            var qWrite = db().from(name).where(pkCol, "=", rows[ri][pkCol]);
            var writeChanges = {};
            writeChanges[overflow] = JSON.stringify(nextOverflow);
            Object.keys(realChanges).forEach(function (k) { writeChanges[k] = realChanges[k]; });
            if (qWrite.updateOne(_stringifyJsonCols(writeChanges))) changed += 1;
          }
        } else {
          // Pure real-column update — single UPDATE for the matching
          // row(s).
          var qSet = db().from(name);
          _applyQuery(qSet, query || {});
          var prepared = _stringifyJsonCols(realChanges);
          if (single) {
            changed += (qSet.updateOne(prepared) ? 1 : 0);
          } else {
            changed += qSet.updateMany(prepared);
          }
        }
      }

      return changed;
    },

    updateMany: function (query, update) {
      return this.update(query, update, { many: true });
    },

    remove: function (query, opts) {
      _validateQueryShape(query || {});
      var q = db().from(name);
      _applyQuery(q, query || {});
      if (opts && opts.many === true) {
        return q.deleteMany();
      }
      return q.deleteOne() ? 1 : 0;
    },

    count: function (query) {
      _validateQueryShape(query || {});
      var q = db().from(name);
      _applyQuery(q, query || {});
      return q.count();
    },

    paginate: function (query, opts) {
      _validateQueryShape(query || {});
      var q = db().from(name);
      _applyQuery(q, query || {});
      var page = q.paginate(opts || {});
      return {
        items:       page.items.map(_decodeRowFromStorage),
        total:       page.total,
        limit:       page.limit,
        offset:      page.offset,
        page:        page.page,
        totalPages:  page.totalPages,
      };
    },
  };
}

module.exports = { collection: collection };
