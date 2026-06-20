"use strict";
/**
 * lib/archive-entry-policy.js — the entry-type extraction policy shared by the
 * ZIP (archive-read) and TAR (archive-tar-read) readers.
 *
 * Special archive entry types — symlinks, hardlinks, device nodes, FIFOs, and
 * sockets — are a malicious-archive vector (symlink traversal out of the
 * extraction root, device-node creation, etc.), so every type is DENIED by
 * default; an operator opts a type in explicitly per archive. Both readers
 * normalized the same default the same way, so the policy + its overlay live
 * here once rather than drifting between the two formats.
 */

var DEFAULT_ENTRY_TYPE_POLICY = Object.freeze({
  symlinks:  false,
  hardlinks: false,
  devices:   false,
  fifos:     false,
  sockets:   false,
});

// normalize(p) — overlay an operator policy onto the all-denied default and
// freeze it. A falsy `p` returns the shared default object (no allocation).
function normalize(p) {
  if (!p) return DEFAULT_ENTRY_TYPE_POLICY;
  return Object.freeze(Object.assign({}, DEFAULT_ENTRY_TYPE_POLICY, p));
}

module.exports = {
  DEFAULT_ENTRY_TYPE_POLICY: DEFAULT_ENTRY_TYPE_POLICY,
  normalize:                 normalize,
};
