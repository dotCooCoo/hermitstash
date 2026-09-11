// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var MIGRATION_FILE_RE = /^(\d+)-([A-Za-z0-9_-]+)\.js$/;
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
