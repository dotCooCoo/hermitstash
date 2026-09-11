// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var { FrameworkError } = require("./framework-error");

var DEFAULT_FILE_NAMES = Object.freeze({
  dbEnc:         "db.enc",
  dbKeyEnc:      "db.key.enc",
  vaultKey:      "vault.key",
  auditTip:      "audit.tip",
  auditSignKey:  "audit-sign.key",
  rowsEnc:       "rows.enc",
  checkpointEnc: "checkpoint.enc",
});

var _overrides = {};

function fileName(logical) {
  if (Object.prototype.hasOwnProperty.call(_overrides, logical)) return _overrides[logical];
  if (Object.prototype.hasOwnProperty.call(DEFAULT_FILE_NAMES, logical)) {
    return DEFAULT_FILE_NAMES[logical];
  }
  throw new FrameworkError(
    "frameworkFiles.fileName: unknown logical file '" + logical + "'",
    "framework-files/unknown");
}

function setFileName(logical, name) {
  if (!Object.prototype.hasOwnProperty.call(DEFAULT_FILE_NAMES, logical)) {
    throw new FrameworkError(
      "frameworkFiles.setFileName: unknown logical file '" + logical + "'",
      "framework-files/unknown");
  }
  if (typeof name !== "string" || name.length === 0 ||
      name.indexOf("/") !== -1 || name.indexOf("\\") !== -1 || name.indexOf("..") !== -1) {
    throw new FrameworkError(
      "frameworkFiles.setFileName: name must be a non-empty bare file name " +
      "(no path separators or '..')", "framework-files/bad-name");
  }
  _overrides[logical] = name;
}

function _resetForTest() { _overrides = {}; }

module.exports = {
  fileName:          fileName,
  setFileName:       setFileName,
  DEFAULT_FILE_NAMES: DEFAULT_FILE_NAMES,
  _resetForTest:     _resetForTest,
};
