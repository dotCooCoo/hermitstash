// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Backward-compat shim. The real helpers live under ./helpers/ — this
 * module re-exports the same surface so legacy `require("./_helpers")`
 * imports keep working during the per-file test layout migration.
 *
 * New test files should import from ./helpers/ directly:
 *   var { check, b } = require("../helpers");
 */
module.exports = require("./helpers");
