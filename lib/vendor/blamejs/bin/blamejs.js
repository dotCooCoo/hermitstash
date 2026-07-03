#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Thin entrypoint — all dispatch logic lives in lib/cli.js so it can
// be driven from tests without spawning a child process.
var cli = require("../lib/cli");

cli.main(process.argv.slice(2)).then(
  function (code) { process.exit(typeof code === "number" ? code : 0); },
  function (err) {
    process.stderr.write("blamejs: " + ((err && err.stack) || String(err)) + "\n");
    process.exit(1);
  }
);
