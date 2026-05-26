"use strict";
/**
 * Layer 0 — b.ai.disclosure.applyAll bundles Art. 50(1) +
 * Art. 50(3) + Art. 50(4) emissions for mixed-modality AI
 * systems.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testApplyAllChatbotDeepfake() {
  var bundle = b.ai.disclosure.applyAll({
    kinds:        ["chatbot", "deepfake"],
    session:      { id: "s1" },
    content:      "imageBytes",
    contentType:  "image",
    jurisdiction: "us-ca",
  });
  check("applyAll: both chatbot + deepfake disclosures present",
    bundle.disclosures.chatbot && bundle.disclosures.deepfake);
  check("applyAll: chatbot Art. 50(1)",
    bundle.disclosures.chatbot.article === "Art. 50(1)");
  check("applyAll: deepfake Art. 50(4) + US-CA cross-walk",
    bundle.disclosures.deepfake.crossWalk.indexOf("us-ca/AB-853 §22949.91") !== -1);
}

async function testApplyAllEmotion() {
  var bundle = b.ai.disclosure.applyAll({
    kinds:              ["emotion"],
    emotionSystemType:  "biometric-categorisation",
  });
  check("applyAll: emotion-only bundle",
    bundle.disclosures.emotion && bundle.disclosures.emotion.systemType === "biometric-categorisation");
  check("applyAll: emotion-only doesn't emit other kinds",
    !bundle.disclosures.chatbot && !bundle.disclosures.deepfake);
}

async function testApplyAllAllThree() {
  var bundle = b.ai.disclosure.applyAll({
    kinds:        ["chatbot", "deepfake", "emotion"],
    session:      { id: "s2" },
    content:      "video",
    contentType:  "video",
  });
  check("applyAll: all three kinds emit together",
    bundle.disclosures.chatbot && bundle.disclosures.deepfake && bundle.disclosures.emotion);
}

async function testApplyAllRefusesBadScenario() {
  var refused = null;
  try { b.ai.disclosure.applyAll(null); } catch (e) { refused = e; }
  check("applyAll: null scenario refused",
    refused && /bad-scenario/.test(refused.code || refused.message));
  var refused2 = null;
  try { b.ai.disclosure.applyAll({ kinds: [] }); } catch (e) { refused2 = e; }
  check("applyAll: empty kinds array refused",
    refused2 && /bad-scenario/.test(refused2.code || refused2.message));
  var refused3 = null;
  try { b.ai.disclosure.applyAll({ kinds: ["chatbot"] }); } catch (e) { refused3 = e; }
  check("applyAll: chatbot without session refused",
    refused3 && /session is required/.test(refused3.message || ""));
  var refused4 = null;
  try { b.ai.disclosure.applyAll({ kinds: ["unknown-kind"] }); } catch (e) { refused4 = e; }
  check("applyAll: unknown kind refused",
    refused4 && /unknown kind/.test(refused4.message || ""));
}

async function testApplyAllAtomicValidation() {
  // Codex P1 on v0.12.25 PR #176 — applyAll must validate the
  // ENTIRE scenario before emitting anything. If a later kind
  // throws (missing contentType, unknown kind), earlier kinds
  // (chatbot session mutation, audit emission) must not have
  // fired.
  var events = [];
  var fakeAudit = { safeEmit: function (e) { events.push(e); } };
  var session = { id: "s-atom" };
  var refused = null;
  try {
    b.ai.disclosure.applyAll({
      kinds:       ["chatbot", "deepfake"],
      session:     session,
      content:     "imageBytes",
      // contentType missing — deepfake validation will fail
      audit:       fakeAudit,
    });
  } catch (e) { refused = e; }
  check("applyAll: bundled call with invalid later kind throws",
    refused !== null);
  check("applyAll: session NOT mutated when bundle validation fails",
    session.aiDisclosureEmitted !== true);
  check("applyAll: no audit events emitted when bundle validation fails",
    events.length === 0);
}

async function testApplyAllSharedAuditPropagated() {
  var events = [];
  var fakeAudit = { safeEmit: function (e) { events.push(e); } };
  b.ai.disclosure.applyAll({
    kinds:        ["chatbot", "emotion"],
    session:      { id: "s3" },
    audit:        fakeAudit,
  });
  check("applyAll: shared audit captures every emission",
    events.length >= 2 &&
    events.some(function (e) { return e.action === "ai-act/chatbot-disclosure-applied"; }) &&
    events.some(function (e) { return e.action === "ai-act/emotion-disclosure-applied"; }));
}

async function run() {
  await testApplyAllChatbotDeepfake();
  await testApplyAllEmotion();
  await testApplyAllAllThree();
  await testApplyAllRefusesBadScenario();
  await testApplyAllAtomicValidation();
  await testApplyAllSharedAuditPropagated();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[ai-disclosure-apply-all] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
