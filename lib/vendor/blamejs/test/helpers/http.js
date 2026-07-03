// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * HTTP test helpers — listenOnRandomPort utility.
 *
 * As of v0.2.38 this is a thin re-export of `b.testing.listenOnRandomPort`
 * — the canonical implementation lives in lib/testing.js so operators
 * get the same helper the framework's own smoke suite uses.
 */

var b = require("../../index.js");

module.exports = {
  listenOnRandomPort: b.testing.listenOnRandomPort,
};
