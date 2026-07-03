// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * migration-files — shared filename-shape primitive.
 *
 * Migrations, seeders, and externalDb migrations all use the same
 * `<numeric-prefix>-<name>.js` file convention. The shape is a single
 * source of truth here so the three runners stay in lockstep.
 *
 *   0001-initial-schema.js
 *   0002-add-users-table.js
 *   0042-rename-column.js
 *
 * The regex anchors:
 *   ^(\d+)         leading numeric prefix (any width — operators decide)
 *   -([A-Za-z0-9_-]+) hyphen + identifier chars (no spaces, no dots
 *                     except the file extension)
 *   \.js$          .js extension
 */

var MIGRATION_FILE_RE = /^(\d+)-([A-Za-z0-9_-]+)\.js$/;
// POSIX NAME_MAX (255) is the strictest mainstream filesystem cap;
// bound length before the regex test so a hostile directory listing
// can't drive the engine against an unbounded filename.
var MIGRATION_FILE_NAME_MAX_LENGTH = 255;

function isMigrationFileName(name) {
  return typeof name === "string" &&
         name.length > 0 &&
         name.length <= MIGRATION_FILE_NAME_MAX_LENGTH &&
         MIGRATION_FILE_RE.test(name);
}

module.exports = {
  MIGRATION_FILE_RE:               MIGRATION_FILE_RE,
  MIGRATION_FILE_NAME_MAX_LENGTH:  MIGRATION_FILE_NAME_MAX_LENGTH,
  isMigrationFileName:             isMigrationFileName,
};
