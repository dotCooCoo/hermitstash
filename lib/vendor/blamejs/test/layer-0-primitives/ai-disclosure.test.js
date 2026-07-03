// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.ai.disclosure.chatbot + .deepfake + .emotion
 * (EU AI Act Art. 50 transparency obligations).
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

function _makeFakeAudit() {
  var events = [];
  return {
    safeEmit: function (e) { events.push(e); },
    events:   events,
  };
}

async function testChatbotFirstContact() {
  var audit = _makeFakeAudit();
  var d = b.ai.disclosure.chatbot({ id: "s1" }, {
    placement: "first-message",
    audit:     audit,
  });
  check("chatbot: shouldEmit true on first contact (placement first-message)", d.shouldEmit);
  check("chatbot: carries Art. 50(1) reference", d.article === "Art. 50(1)");
  check("chatbot: default text is generic AI interaction notice",
    d.text === "You are interacting with an AI system.");
  check("chatbot: audit event emitted",
    audit.events.length === 1 && audit.events[0].action === "ai-act/chatbot-disclosure-applied");
}

async function testChatbotPostFirstContact() {
  var d = b.ai.disclosure.chatbot({ id: "s2", aiDisclosureEmitted: true }, {
    placement: "first-message",
  });
  check("chatbot: shouldEmit false after first-message already emitted", !d.shouldEmit);
}

async function testChatbotFirstMessageMutatesSession() {
  // Codex P1B on v0.12.12 PR #163 — first-message must mutate
  // session.aiDisclosureEmitted so the next call sees it.
  var session = { id: "s-codex-b" };
  var d1 = b.ai.disclosure.chatbot(session, { placement: "first-message" });
  check("chatbot: first call emits", d1.shouldEmit === true);
  check("chatbot: session.aiDisclosureEmitted mutated after first emit",
    session.aiDisclosureEmitted === true);
  var d2 = b.ai.disclosure.chatbot(session, { placement: "first-message" });
  check("chatbot: second call on same session no longer emits", d2.shouldEmit === false);
}

async function testChatbotOnRequestGatesOnRequested() {
  // Codex P1A on v0.12.12 PR #163 — "on-request" without
  // opts.requested must NOT emit (otherwise on-request collapses
  // to always-on).
  var d1 = b.ai.disclosure.chatbot({ id: "s-or-1" }, { placement: "on-request" });
  check("chatbot: on-request without opts.requested does not emit", d1.shouldEmit === false);
  var d2 = b.ai.disclosure.chatbot({ id: "s-or-2" }, {
    placement: "on-request",
    requested: true,
  });
  check("chatbot: on-request with opts.requested:true emits", d2.shouldEmit === true);
}

async function testChatbotAlwaysPlacement() {
  var d = b.ai.disclosure.chatbot({ id: "s3", aiDisclosureEmitted: true }, {
    placement: "always",
  });
  check("chatbot: shouldEmit true under placement: always regardless of prior emission",
    d.shouldEmit);
}

async function testChatbotRefusesBadJurisdiction() {
  var refused = null;
  try {
    b.ai.disclosure.chatbot({ id: "s4" }, { jurisdiction: "not-a-jurisdiction" });
  } catch (e) { refused = e; }
  check("chatbot: bad jurisdiction refused with typed error",
    refused && /bad-jurisdiction/.test(refused.code || refused.message));
  check("chatbot: refusal is a b.ai.disclosure.AiDisclosureError",
    refused instanceof b.ai.disclosure.AiDisclosureError);
}

async function testDeepfakeImage() {
  var audit = _makeFakeAudit();
  var d = b.ai.disclosure.deepfake("imageBytes", {
    contentType: "image",
    placement:   "both",
    audit:       audit,
  });
  check("deepfake: image carries visible label", typeof d.label === "string" && d.label.length > 0);
  check("deepfake: image carries machine-readable metadata", d.metadata !== null && d.metadata.ai_generated === true);
  check("deepfake: schema reserved for C2PA v0.12.21 hand-off",
    d.metadata.schema === "c2pa-v1.4-ready");
  check("deepfake: default jurisdiction is eu (cross-walk single-entry)",
    d.crossWalk.length === 1 && d.crossWalk[0] === "eu-ai-act/Art. 50(4)");
  check("deepfake: audit event emitted",
    audit.events.length === 1 && audit.events[0].action === "ai-act/deepfake-disclosure-applied");
}

async function testDeepfakeCrossWalkCalifornia() {
  var d = b.ai.disclosure.deepfake("imageBytes", {
    contentType:  "image",
    jurisdiction: "us-ca",
  });
  check("deepfake: us-ca jurisdiction adds AB-853 cross-walk entry",
    d.crossWalk.length === 2 && d.crossWalk.indexOf("us-ca/AB-853 §22949.91") !== -1);
}

async function testDeepfakeCrossWalkChina() {
  var d = b.ai.disclosure.deepfake("imageBytes", {
    contentType:  "image",
    jurisdiction: "cn",
  });
  check("deepfake: cn jurisdiction adds CAC GenAI Art. 12 cross-walk entry",
    d.crossWalk.length === 2 && d.crossWalk.indexOf("cn/CAC-GenAI Measures Art. 12") !== -1);
}

async function testDeepfakeRefusesBadContentType() {
  var refused = null;
  try {
    b.ai.disclosure.deepfake("bytes", { contentType: "spreadsheet" });
  } catch (e) { refused = e; }
  check("deepfake: invalid contentType refused upfront",
    refused && /bad-arg/.test(refused.code || refused.message));
}

async function testDeepfakeLabelOnlyPlacement() {
  var d = b.ai.disclosure.deepfake("bytes", { contentType: "text", placement: "label" });
  check("deepfake: placement: label yields no metadata payload", d.metadata === null);
  check("deepfake: placement: label yields visible label", typeof d.label === "string");
}

async function testDeepfakeMetadataOnlyPlacement() {
  var d = b.ai.disclosure.deepfake("bytes", { contentType: "video", placement: "metadata" });
  check("deepfake: placement: metadata yields no visible label", d.label === null);
  check("deepfake: placement: metadata yields structured payload",
    d.metadata !== null && d.metadata.content_type === "video");
}

async function testEmotionDisclosure() {
  var audit = _makeFakeAudit();
  var d = b.ai.disclosure.emotion({ systemType: "emotion", audit: audit });
  check("emotion: carries Art. 50(3) reference", d.article === "Art. 50(3)");
  check("emotion: audit event emitted",
    audit.events.length === 1 && audit.events[0].action === "ai-act/emotion-disclosure-applied");
}

async function testEmotionBiometricCategorisation() {
  var d = b.ai.disclosure.emotion({ systemType: "biometric-categorisation" });
  check("emotion: biometric-categorisation systemType accepted",
    d.systemType === "biometric-categorisation");
}

async function testAuditDropSilent() {
  // Per rule §5 — hot-path observability sinks drop silent. Pass an
  // audit whose safeEmit throws + verify the primitive doesn't fail.
  var throwingAudit = { safeEmit: function () { throw new Error("audit-bus-down"); } };
  var d = b.ai.disclosure.chatbot({ id: "s5" }, {
    placement: "first-message",
    audit:     throwingAudit,
  });
  check("chatbot: audit emit failure does not crash the disclosure path",
    d.shouldEmit === true);
}

async function run() {
  await testChatbotFirstContact();
  await testChatbotFirstMessageMutatesSession();
  await testChatbotOnRequestGatesOnRequested();
  await testChatbotPostFirstContact();
  await testChatbotAlwaysPlacement();
  await testChatbotRefusesBadJurisdiction();
  await testDeepfakeImage();
  await testDeepfakeCrossWalkCalifornia();
  await testDeepfakeCrossWalkChina();
  await testDeepfakeRefusesBadContentType();
  await testDeepfakeLabelOnlyPlacement();
  await testDeepfakeMetadataOnlyPlacement();
  await testEmotionDisclosure();
  await testEmotionBiometricCategorisation();
  await testAuditDropSilent();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[ai-disclosure] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
