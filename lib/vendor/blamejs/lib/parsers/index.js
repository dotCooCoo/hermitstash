// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var safeEnv  = require("./safe-env");
var safeIni  = require("./safe-ini");
var safeToml = require("./safe-toml");
var safeXml  = require("./safe-xml");
var safeYaml = require("./safe-yaml");
var bodyParser = require("../middleware/body-parser");

module.exports = {
  xml:       safeXml,
  toml:      safeToml,
  yaml:      safeYaml,
  env:       safeEnv,
  ini:       safeIni,
  json:      bodyParser.parseJson,
  multipart: bodyParser.parseMultipart,
};
