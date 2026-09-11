// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var CARRIED_ACTOR_FIELDS = ["ip", "userAgent", "sessionId"];

function actorShape(actor) {
  if (!actor || typeof actor !== "object") return { id: "<system>", userId: null };
  var shaped = { id: actor.id, userId: actor.id, roles: actor.roles || [] };
  CARRIED_ACTOR_FIELDS.forEach(function (field) {
    if (actor[field] !== undefined) shaped[field] = actor[field];
  });
  return shaped;
}

function safeAudit(auditImpl, action, actor, metadata) {
  try {
    auditImpl.safeEmit({
      action: action,
      actor:  actorShape(actor),
      outcome: _outcomeFor(action),
      metadata: metadata || {},
    });
  } catch (_e) { /* drop-silent — audit failures don't crash the call */ }
}

function _outcomeFor(action) {
  if (typeof action !== "string") return "success";
  if (action.indexOf("denied")          >= 0) return "failure";
  if (action.indexOf("drop")            >= 0) return "failure";
  if (action.indexOf("threw")           >= 0) return "failure";
  if (action.indexOf("different_args")  >= 0) return "failure";
  if (action.indexOf("miss")            >= 0) return "failure";
  if (action.indexOf("not_implemented") >= 0) return "failure";
  return "success";
}

module.exports = {
  safeAudit:  safeAudit,
  actorShape: actorShape,
};
