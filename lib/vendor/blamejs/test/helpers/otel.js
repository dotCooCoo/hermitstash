// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fake @opentelemetry/api for tests that verify the framework routes
 * through the real-OTel path instead of the pass-through.
 *
 * As of v0.2.38 this is a thin re-export of `b.testing.makeFakeOtelApi`
 * — the canonical implementation lives in lib/testing.js so operators
 * get the same fake the framework's own tracing/observability tests use.
 */

var b = require("../../index.js");

module.exports = { makeFakeOtelApi: b.testing.makeFakeOtelApi };
