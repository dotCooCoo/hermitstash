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
// to "success"; `metadata` defaults to `{}`.
function emit(action, metadata, outcome) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome || "success",
      metadata: metadata || {},
    });
  } catch (_e) { /* drop-silent — audit best-effort */ }
}

// emitToSink(opts, action, outcome, metadata) — drop-silent audit emit to an
// OPERATOR-SUPPLIED sink threaded through `opts.audit`, the no-op-when-absent
// variant the archive reader / tar-reader / writer share verbatim: forward the
// event only when `opts.audit` exposes a `safeEmit`, otherwise stay silent.
// Distinct from emit() (which targets the framework's GLOBAL audit()) — here the
// caller carries the sink in opts, so a reader/writer with no audit configured
// emits nothing. (Callers whose payload carries extra top-level fields — e.g.
// http-client's `resource` — keep their own wrapper; this is the bare
// action/outcome/metadata shape.)
function emitToSink(opts, action, outcome, metadata) {
  if (!opts || !opts.audit || typeof opts.audit.safeEmit !== "function") return;
  try {
    opts.audit.safeEmit({ action: action, outcome: outcome, metadata: metadata });
  } catch (_e) { /* drop-silent — operator audit sink must never crash the caller */ }
}

// gatedReasonEmitter({ audit, sink?, extra? }) — build a gated drop-silent
// emitter `(action, info, outcome)` that records a structured top-level `reason`
// (hoisted from `info.reason`) alongside the audit metadata. The gated +
// reason-hoisting sibling of emit() / b.audit.namespaced, for the primitives
// (backup / restore / scheduler / config-drift / legal-hold) that emit a reason
// the audit chain surfaces as a first-class field. `audit` is the gate flag
// (false disables); `sink` is an optional operator-supplied audit target (the
// no-op-without-safeEmit guard the hand-rolled `auditInstance || audit()`
// pattern carried); `extra(info)` optionally returns more top-level event
// fields (e.g. legal-hold's `resource`). Routes through b.audit.namespaced, so
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
  gatedReasonEmitter: gatedReasonEmitter,
};
