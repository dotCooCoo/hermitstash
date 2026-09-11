// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodeCrypto = require("node:crypto");

function sha1Hex(data) {
  return nodeCrypto.createHash("sha1").update(data).digest("hex");
}

module.exports = { sha1Hex: sha1Hex };
