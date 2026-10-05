// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var requestHelpers = require("./request-helpers");

var CARRIED_ACTOR_FIELDS = ["ip", "userAgent", "sessionId"];
var SYSTEM_ACTOR_ID = "<system>";

function _identityName(actor) {
  var present = requestHelpers.actorIdentityFields(actor);
  if (present.length === 0) return null;
  var value = present[0].value;
  return typeof value === "number" ? String(value) : value;
}

function actorShape(actor) {
  if (actor === null || actor === undefined) {
    return { id: SYSTEM_ACTOR_ID, userId: null };
  }
  if (typeof actor !== "object") {
    var named = (typeof actor === "string" || typeof actor === "number")
      ? _identityName({ id: actor }) : null;
    if (named === null) return { id: SYSTEM_ACTOR_ID, userId: null };
    return { id: named, userId: named, roles: [] };
  }
  var name = _identityName(actor);
  var shaped = {
    id:     name === null ? SYSTEM_ACTOR_ID : name,
    userId: name,
    roles:  actor.roles || [],
  };
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
