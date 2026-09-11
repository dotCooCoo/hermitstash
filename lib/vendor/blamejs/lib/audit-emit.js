// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// audit-emit — the stateless drop-silent audit emitter with a metadata-first,
// success-default signature `(action, metadata, outcome?)`. Many primitives —
// the mail servers and DAV bridge, the A2A task store, the compliance posture
// tracker, the MCP tool registry, the idempotency-key middleware — emit audit
// events where the per-event detail (metadata) is almost always supplied and
// the outcome is almost always "this happened", so they pass metadata second
// and let outcome default to "success". They route through the drop-silent
// audit.safeEmit so a misbehaving sink never crashes the request. Unlike
// b.audit.namespaced (gated, action-prefixed, outcome-first), this is ungated
// and passes the action verbatim — matching what each of them hand-rolled.
//
// This module self-lazy-requires audit so a consumer can `require("./audit-emit")`
// at the top of the file without re-introducing the audit load cycle that the
// per-file `lazyRequire(() => require("./audit"))` was guarding against.

var lazyRequire = require("./lazy-require");
var audit = lazyRequire(function () { return require("./audit"); });

// emit(action, metadata, outcome?) — drop-silent audit emit. `outcome` defaults
function emit(action, metadata, outcome) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome || "success",
      metadata: metadata || {},
    });
  } catch (_e) { /* drop-silent — audit best-effort */ }
}

// Drop-silent audit emit to the sink on `opts.audit`, if there is one.
function emitToSink(opts, action, outcome, metadata) {
  if (!opts || !opts.audit || typeof opts.audit.safeEmit !== "function") return;
  try {
    opts.audit.safeEmit({ action: action, outcome: outcome, metadata: metadata });
  } catch (_e) { /* drop-silent — operator audit sink must never crash the caller */ }
}

function dualEmitter(opts) {
  if (!opts || !opts.audit) return emit;
  if (opts.audit === audit()) return emit;
  return function (action, metadata, outcome) {
    emit(action, metadata, outcome);
    emitToSink(opts, action, outcome || "success", metadata || {});
  };
}

// gatedReasonEmitter({ audit, sink?, extra? }) — build a gated drop-silent
// the same redaction + drop-silent guarantees apply.
function gatedReasonEmitter(opts) {
  opts = opts || {};
  var ns = audit().namespaced(null, { audit: opts.audit, sink: opts.sink });
  var extra = typeof opts.extra === "function" ? opts.extra : null;
  return function (action, info, outcome) {
    var fields = { reason: (info && info.reason) || null };
    if (extra) {
      var more = extra(info);
      if (more) {
        for (var k in more) {
          if (Object.prototype.hasOwnProperty.call(more, k)) fields[k] = more[k];
        }
      }
    }
    ns(action, outcome, info, fields);
  };
}

module.exports = {
  emit:               emit,
  emitToSink:         emitToSink,
  dualEmitter:        dualEmitter,
  gatedReasonEmitter: gatedReasonEmitter,
};
