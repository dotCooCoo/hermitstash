// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var DEFAULT_ENTRY_TYPE_POLICY = Object.freeze({
  symlinks:  false,
  hardlinks: false,
  devices:   false,
  fifos:     false,
  sockets:   false,
});

function normalize(p) {
  if (!p) return DEFAULT_ENTRY_TYPE_POLICY;
  return Object.freeze(Object.assign({}, DEFAULT_ENTRY_TYPE_POLICY, p));
}

module.exports = {
  DEFAULT_ENTRY_TYPE_POLICY: DEFAULT_ENTRY_TYPE_POLICY,
  normalize:                 normalize,
};
