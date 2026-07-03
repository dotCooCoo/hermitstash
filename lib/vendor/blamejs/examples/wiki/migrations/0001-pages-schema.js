// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Pages schema for the wiki + FTS5 virtual table for /search recipe.
 *
 * Schema columns:
 *   group, slug — composite PK so the same slug can exist in different groups
 *   title       — display title
 *   body        — operator-trusted HTML (rendered raw via {{{ }}})
 *   updatedAt   — unix ms
 *   updatedBy   — user id of the last editor (admin)
 *
 * FTS5 mirror is operator-side; we ship it here so /search works
 * out-of-the-box and serves as the "search recipe" the docs reference.
 * Triggers keep the FTS5 table in sync with the pages table on insert /
 * update / delete — same shape every modern SQLite app uses.
 */

module.exports = {
  description: "Create pages table + FTS5 search mirror",
  up: function (db) {
    db["exec"](
      "CREATE TABLE IF NOT EXISTS pages (" +
      "  groupName  TEXT NOT NULL," +
      "  slug       TEXT NOT NULL," +
      "  title      TEXT NOT NULL," +
      "  body       TEXT NOT NULL," +
      "  updatedAt  INTEGER NOT NULL," +
      "  updatedBy  TEXT," +
      "  PRIMARY KEY (groupName, slug)" +
      ")"
    );
    db["exec"]("CREATE INDEX IF NOT EXISTS idx_pages_updatedAt ON pages (updatedAt)");

    // FTS5 virtual table — operator-side recipe. Indexes title + body
    // for full-text search via /search?q=...
    db["exec"](
      "CREATE VIRTUAL TABLE IF NOT EXISTS pages_fts USING fts5(" +
      "  groupName UNINDEXED," +
      "  slug      UNINDEXED," +
      "  title," +
      "  body," +
      "  tokenize = 'porter'" +
      ")"
    );

    // Triggers keep pages_fts in sync with pages. Drop-and-recreate
    // approach inside each trigger keeps the SQL single-statement.
    db["exec"](
      "CREATE TRIGGER IF NOT EXISTS pages_fts_insert AFTER INSERT ON pages BEGIN " +
      "  INSERT INTO pages_fts (groupName, slug, title, body) " +
      "  VALUES (new.groupName, new.slug, new.title, new.body); " +
      "END"
    );
    db["exec"](
      "CREATE TRIGGER IF NOT EXISTS pages_fts_delete AFTER DELETE ON pages BEGIN " +
      "  DELETE FROM pages_fts WHERE groupName = old.groupName AND slug = old.slug; " +
      "END"
    );
    db["exec"](
      "CREATE TRIGGER IF NOT EXISTS pages_fts_update AFTER UPDATE ON pages BEGIN " +
      "  DELETE FROM pages_fts WHERE groupName = old.groupName AND slug = old.slug; " +
      "  INSERT INTO pages_fts (groupName, slug, title, body) " +
      "  VALUES (new.groupName, new.slug, new.title, new.body); " +
      "END"
    );
  },
  down: function (db) {
    db["exec"]("DROP TRIGGER IF EXISTS pages_fts_update");
    db["exec"]("DROP TRIGGER IF EXISTS pages_fts_delete");
    db["exec"]("DROP TRIGGER IF EXISTS pages_fts_insert");
    db["exec"]("DROP TABLE IF EXISTS pages_fts");
    db["exec"]("DROP TABLE IF EXISTS pages");
  },
};
