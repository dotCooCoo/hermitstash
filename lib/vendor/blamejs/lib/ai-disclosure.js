// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.ai.disclosure
 * @nav    Compliance
 * @title  AI Act Art. 50 disclosures
 *
 * @intro
 *   EU AI Act Regulation (EU) 2024/1689 Article 50 transparency
 *   obligations enter force 2026-08-02. This module ships the active
 *   runtime primitives that emit disclosure markup at request time:
 *
 *   - `b.ai.disclosure.chatbot(session, opts)` — Art. 50(1).
 *     Operators interacting with natural persons must disclose the
 *     AI nature of the interaction. Returns the disclosure payload
 *     (visible text / structured metadata) to wire into the response.
 *
 *   - `b.ai.disclosure.deepfake(content, opts)` — Art. 50(4).
 *     Operators emitting AI-generated / AI-manipulated content
 *     (image / audio / video / text) must label the output as
 *     synthetic. Returns the disclosure payload + suggested
 *     embedding points (visible label / C2PA metadata / both).
 *
 *   - `b.ai.disclosure.emotion(opts)` — Art. 50(3). Emotion-
 *     recognition / biometric-categorisation systems must inform
 *     the natural person of operation. Returns the notice payload.
 *
 *   Cross-jurisdiction:
 *     - California AB-853 (effective 2026) — watermarking on
 *       AI-generated content. The deepfake primitive emits both
 *       AI Act Art. 50(4) AND AB-853 markup when `jurisdiction:
 *       "us-ca"` is requested.
 *     - China CAC GenAI Measures — content review marker. Same
 *       primitive handles the cross-walk via the `jurisdiction:
 *       "cn"` opt.
 *
 *   Composition:
 *     - `b.audit-sign` chains every disclosure emission so the
 *       Art. 50 compliance trail is tamper-evident.
 *     - `b.agent.idempotency` (v0.9.22) ensures the chatbot
 *       first-contact disclosure isn't double-emitted across
 *       retry / reconnect.
 *     - `b.contentCredentials` (v0.12.21 — deferred) will wire
 *       C2PA manifest emission alongside the visible label.
 *
 *   Out of scope (this patch):
 *     - C2PA manifest emission — defers to v0.12.21 b.contentCredentials.
 *     - Watermark frame embedding into image/audio/video bytes —
 *       operator's encoder pipeline (this primitive supplies the
 *       label markup; the operator chooses the embed point).
 *     - Real-time prohibited-content moderation — orthogonal,
 *       composes with b.ai.input.refuseIfMalicious.
 *
 * @card
 *   EU AI Act Art. 50 transparency obligation primitives — chatbot
 *   disclosure, deepfake / synthetic-content labels, emotion-
 *   recognition notices. Calendar-locked 2026-08-02.
 */

var { defineClass } = require("./framework-error");

var AiDisclosureError = defineClass("AiDisclosureError", { alwaysPermanent: true });

// Audit emissions route through opts.audit (operator-supplied
// instance) — see _emitAudit below. No framework-side audit
// require needed; the primitive is a pure value-returning function
// with the optional safeEmit-via-opts side-effect.

var DEFAULT_CHATBOT_TEXT = "You are interacting with an AI system.";
var DEFAULT_DEEPFAKE_TEXT = "This content has been generated or manipulated using artificial intelligence.";
var DEFAULT_EMOTION_TEXT = "This system uses AI to recognise emotions or biometrically categorise individuals.";

// Recognised jurisdiction codes. EU is implicit (the AI Act applies
// throughout the Union); US-CA layers in AB-853; CN layers in the
// CAC GenAI Measures.
var SUPPORTED_JURISDICTIONS = ["eu", "us-ca", "cn"];

// Content types eligible for a deepfake notice per Art. 50(4):
// image / audio / video / text. Each carries different recommended
// placement defaults (image+video → both label & metadata; audio →
// audible preamble or metadata; text → visible disclaimer).
var DEEPFAKE_CONTENT_TYPES = ["image", "audio", "video", "text"];

/**
 * @primitive b.ai.disclosure.chatbot
 * @signature b.ai.disclosure.chatbot(session, opts)
 * @since     0.12.12
 * @status    stable
 * @compliance eu-ai-act, ca-ab-853, cac-genai-label
 * @related   b.ai.disclosure.deepfake, b.ai.disclosure.emotion, b.audit
 *
 * EU AI Act Art. 50(1) first-contact disclosure. Operators
 * interacting with natural persons via an AI system must inform
 * the person they are interacting with AI unless it is obvious from
 * the circumstances (Art. 50(1) carve-out). This primitive returns
 * the disclosure payload + emits an audit event per emission so
 * the compliance trail is tamper-evident under `b.audit-sign`.
 *
 * @opts
 *   placement:      "first-message" | "always" | "on-request",  // default "first-message"
 *   language:       string,    // BCP 47 tag; defaults to en
 *   text:           string,    // override the default disclosure text
 *   jurisdiction:   string,    // "eu" (default) | "us-ca" | "cn"
 *   audit:          object,    // b.audit instance for tamper-evident logging
 *   correlationId:  string,    // audit chain correlation
 *
 * @example
 *   var disclosure = b.ai.disclosure.chatbot({ id: "session-42" }, {
 *     placement: "first-message",
 *     language:  "en",
 *   });
 *   // disclosure.text   → "You are interacting with an AI system."
 *   // disclosure.shouldEmit → true (first contact)
 *   // operator wires disclosure.text into the response payload
 */
function chatbot(session, opts) {
  opts = opts || {};
  if (!session || typeof session !== "object") {
    throw new AiDisclosureError("ai-disclosure/bad-session",
      "chatbot: session must be an object carrying at minimum an id");
  }
  if (typeof session.id !== "string" || session.id.length === 0) {
    throw new AiDisclosureError("ai-disclosure/bad-session",
      "chatbot: session.id must be a non-empty string");
  }
  var placement = opts.placement || "first-message";
  if (placement !== "first-message" && placement !== "always" && placement !== "on-request") {
    throw new AiDisclosureError("ai-disclosure/bad-arg",
      "chatbot: opts.placement must be \"first-message\" (default) | \"always\" | \"on-request\"; got " +
      JSON.stringify(placement));
  }
  var jurisdiction = opts.jurisdiction || "eu";
  _validateJurisdiction(jurisdiction, "chatbot");
  var text = typeof opts.text === "string" && opts.text.length > 0
    ? opts.text
    : DEFAULT_CHATBOT_TEXT;
  // "on-request" placement gates on
  // the operator's explicit `opts.requested: true` signal. Without
  // it, "on-request" collapsed into "always" semantics and emitted
  // every call. The operator wires this from an explicit user
  // gesture ("show me what AI features are in use") or an admin
  // toggle. Default false so the gate stays closed when the opt
  // isn't passed.
  var requested = opts.requested === true;
  var firstSeen = !session.aiDisclosureEmitted;
  var shouldEmit = placement === "always" ||
    (placement === "first-message" && firstSeen) ||
    (placement === "on-request" && requested);
  var emission = {
    text:           text,
    language:       opts.language || "en",
    jurisdiction:   jurisdiction,
    placement:      placement,
    shouldEmit:     shouldEmit,
    article:        "Art. 50(1)",
    regulation:     "Regulation (EU) 2024/1689",
  };
  if (shouldEmit) {
    // Mark the session so subsequent
    // calls with the same session under "first-message" placement
    // see `aiDisclosureEmitted: true` and return shouldEmit=false.
    // Without this mutation operators had to remember to flip the
    // flag themselves; the default would re-emit on every call.
    if (placement === "first-message") {
      session.aiDisclosureEmitted = true;
    }
    _emitAudit(opts, "ai-act/chatbot-disclosure-applied", "success", {
      sessionId:      session.id,
      placement:      placement,
      jurisdiction:   jurisdiction,
      correlationId:  opts.correlationId || null,
    });
  }
  return emission;
}

/**
 * @primitive b.ai.disclosure.deepfake
 * @signature b.ai.disclosure.deepfake(content, opts)
 * @since     0.12.12
 * @status    stable
 * @compliance eu-ai-act, ca-ab-853, cac-genai-label
 * @related   b.ai.disclosure.chatbot, b.contentCredentials
 *
 * EU AI Act Art. 50(4) synthetic-content disclosure. Operators
 * emitting AI-generated or AI-manipulated content (image / audio /
 * video / text) must label the output as synthetic in a clear and
 * machine-readable manner. This primitive returns the disclosure
 * payload (visible label + structured metadata) the operator wires
 * into the encoder / response pipeline. C2PA manifest emission is
 * handled by `b.contentCredentials`; this primitive supplies the label
 * markup and the metadata schema that the C2PA adapter consumes.
 *
 * @opts
 *   contentType:   "image" | "audio" | "video" | "text",        // required
 *   placement:     "label" | "metadata" | "both",                // default "both"
 *   jurisdiction:  string,    // "eu" (default) | "us-ca" | "cn"
 *   language:      string,    // BCP 47 tag; defaults to en
 *   text:          string,    // override the default disclosure text
 *   audit:         object,
 *   correlationId: string,
 *
 * @example
 *   var disclosure = b.ai.disclosure.deepfake(imageBytes, {
 *     contentType:  "image",
 *     placement:    "both",
 *     jurisdiction: "us-ca",
 *   });
 *   // disclosure.label    → "This content has been generated ..."
 *   // disclosure.metadata → { ai_generated: true, schema: "c2pa-v1.4-ready" }
 *   // disclosure.crossWalk → ["eu-ai-act/Art. 50(4)", "us-ca/AB-853 §22949.91"]
 */
function deepfake(content, opts) {
  opts = opts || {};
  if (content === undefined || content === null) {
    throw new AiDisclosureError("ai-disclosure/bad-content",
      "deepfake: content is required (Buffer | string | { type, bytes })");
  }
  if (typeof opts.contentType !== "string" ||
      DEEPFAKE_CONTENT_TYPES.indexOf(opts.contentType) === -1) {
    throw new AiDisclosureError("ai-disclosure/bad-arg",
      "deepfake: opts.contentType must be one of " +
      DEEPFAKE_CONTENT_TYPES.join(" | ") + "; got " + JSON.stringify(opts.contentType));
  }
  var placement = opts.placement || "both";
  if (placement !== "label" && placement !== "metadata" && placement !== "both") {
    throw new AiDisclosureError("ai-disclosure/bad-arg",
      "deepfake: opts.placement must be \"label\" | \"metadata\" | \"both\" (default); got " +
      JSON.stringify(placement));
  }
  var jurisdiction = opts.jurisdiction || "eu";
  _validateJurisdiction(jurisdiction, "deepfake");
  var text = typeof opts.text === "string" && opts.text.length > 0
    ? opts.text
    : DEFAULT_DEEPFAKE_TEXT;
  var crossWalk = ["eu-ai-act/Art. 50(4)"];
  if (jurisdiction === "us-ca") crossWalk.push("us-ca/AB-853 §22949.91");
  if (jurisdiction === "cn") crossWalk.push("cn/CAC-GenAI Measures Art. 12");
  var emission = {
    label:          placement === "metadata" ? null : text,
    metadata:       placement === "label" ? null : {
      ai_generated:  true,
      content_type:  opts.contentType,
      schema:        "c2pa-v1.4-ready",                                              // v0.12.21 b.contentCredentials lights this up
      jurisdiction:  jurisdiction,
      regulation:    "Regulation (EU) 2024/1689",
      article:       "Art. 50(4)",
    },
    language:       opts.language || "en",
    contentType:    opts.contentType,
    placement:      placement,
    crossWalk:      crossWalk,
  };
  _emitAudit(opts, "ai-act/deepfake-disclosure-applied", "success", {
    contentType:    opts.contentType,
    placement:      placement,
    jurisdiction:   jurisdiction,
    correlationId:  opts.correlationId || null,
  });
  return emission;
}

/**
 * @primitive b.ai.disclosure.emotion
 * @signature b.ai.disclosure.emotion(opts)
 * @since     0.12.12
 * @status    stable
 * @compliance eu-ai-act
 * @related   b.ai.disclosure.chatbot, b.ai.disclosure.deepfake
 *
 * EU AI Act Art. 50(3) emotion-recognition / biometric-
 * categorisation disclosure. Operators deploying these systems
 * must inform the natural person of operation. Returns the notice
 * payload the operator wires into the consent / pre-interaction
 * flow.
 *
 * @opts
 *   language:      string,
 *   text:          string,
 *   systemType:    "emotion" | "biometric-categorisation",   // default "emotion"
 *   audit:         object,
 *   correlationId: string,
 *
 * @example
 *   var notice = b.ai.disclosure.emotion({ systemType: "emotion" });
 *   // notice.text → "This system uses AI to recognise emotions ..."
 *   // notice.article → "Art. 50(3)"
 */
function emotion(opts) {
  opts = opts || {};
  var systemType = opts.systemType || "emotion";
  if (systemType !== "emotion" && systemType !== "biometric-categorisation") {
    throw new AiDisclosureError("ai-disclosure/bad-arg",
      "emotion: opts.systemType must be \"emotion\" (default) | \"biometric-categorisation\"; got " +
      JSON.stringify(systemType));
  }
  var text = typeof opts.text === "string" && opts.text.length > 0
    ? opts.text
    : DEFAULT_EMOTION_TEXT;
  var emission = {
    text:           text,
    language:       opts.language || "en",
    systemType:     systemType,
    article:        "Art. 50(3)",
    regulation:     "Regulation (EU) 2024/1689",
  };
  _emitAudit(opts, "ai-act/emotion-disclosure-applied", "success", {
    systemType:     systemType,
    correlationId:  opts.correlationId || null,
  });
  return emission;
}

function _validateJurisdiction(jurisdiction, primitive) {
  if (SUPPORTED_JURISDICTIONS.indexOf(jurisdiction) === -1) {
    throw new AiDisclosureError("ai-disclosure/bad-jurisdiction",
      primitive + ": opts.jurisdiction must be one of " +
      SUPPORTED_JURISDICTIONS.join(" | ") + " (eu = default; us-ca = California AB-853; " +
      "cn = China CAC GenAI Measures); got " + JSON.stringify(jurisdiction));
  }
}

function _emitAudit(opts, action, outcome, metadata) {
  if (!opts.audit || typeof opts.audit.safeEmit !== "function") return;
  try {
    opts.audit.safeEmit({
      action:    action,
      outcome:   outcome,
      metadata:  metadata || {},
    });
  } catch (_e) {
    // drop-silent — audit emit failure cannot crash the disclosure
    // path. The Art. 50 obligation is the user-facing notice the
    // primitive returns; the audit emission is a parallel best-
    // effort chain-of-custody record. Throwing here would refuse
    // the disclosure to defend the audit chain, which fails the
    // wrong direction (the regulatory contract is satisfied by
    // emitting the notice; the audit trail backs it up).
  }
}

/**
 * @primitive b.ai.disclosure.applyAll
 * @signature b.ai.disclosure.applyAll(scenario)
 * @since     0.12.25
 * @status    stable
 * @compliance eu-ai-act, ca-ab-853, cac-genai-label
 * @related   b.ai.disclosure.chatbot, b.ai.disclosure.deepfake, b.ai.disclosure.emotion
 *
 * Bundles multiple Art. 50 disclosures into a single call.
 * Operators with mixed-modality AI systems (e.g. a chatbot that
 * also generates images) declare which obligations apply via
 * `scenario.kinds` and the primitive composes the per-obligation
 * emit calls in one pass. Returns `{ disclosures: { chatbot?,
 * deepfake?, emotion? } }` with each entry being the per-
 * primitive emission payload.
 *
 * @opts
 *   scenario.kinds:        ["chatbot", "deepfake", "emotion"]      // required (subset)
 *   scenario.session:      object,            // required when "chatbot" is included
 *   scenario.content:      string | Buffer,   // required when "deepfake" is included
 *   scenario.contentType:  string,            // required when "deepfake" is included
 *   scenario.jurisdiction: string,            // forwarded to all
 *   scenario.language:     string,
 *   scenario.audit:        object,
 *   scenario.correlationId: string,
 *
 * @example
 *   var bundle = b.ai.disclosure.applyAll({
 *     kinds:        ["chatbot", "deepfake"],
 *     session:      { id: "s1" },
 *     content:      imageBytes,
 *     contentType:  "image",
 *     jurisdiction: "us-ca",
 *   });
 *   // bundle.disclosures.chatbot.text  → "You are interacting with an AI system."
 *   // bundle.disclosures.deepfake.label → "This content has been ..."
 */
function applyAll(scenario) {
  if (!scenario || typeof scenario !== "object") {
    throw new AiDisclosureError("ai-disclosure/bad-scenario",
      "applyAll: scenario must be an object with kinds + per-kind required fields");
  }
  if (!Array.isArray(scenario.kinds) || scenario.kinds.length === 0) {
    throw new AiDisclosureError("ai-disclosure/bad-scenario",
      "applyAll: scenario.kinds must be a non-empty array of " +
      "\"chatbot\" / \"deepfake\" / \"emotion\"");
  }
  // Validate every kind +
  // per-kind required field UP FRONT, before any emission.
  // Previously a later-kind failure (e.g. deepfake missing
  // contentType, unknown trailing kind) ran AFTER earlier kinds
  // had already mutated session.aiDisclosureEmitted + emitted
  // audit events — non-atomic execution suppressed future
  // first-message disclosures even though applyAll threw.
  var SUPPORTED_KINDS = ["chatbot", "deepfake", "emotion"];
  for (var vi = 0; vi < scenario.kinds.length; vi += 1) {
    var vk = scenario.kinds[vi];
    if (SUPPORTED_KINDS.indexOf(vk) === -1) {
      throw new AiDisclosureError("ai-disclosure/bad-scenario",
        "applyAll: unknown kind " + JSON.stringify(vk) +
        " — supported: \"chatbot\" / \"deepfake\" / \"emotion\"");
    }
    if (vk === "chatbot" && !scenario.session) {
      throw new AiDisclosureError("ai-disclosure/bad-scenario",
        "applyAll: scenario.session is required when kinds includes \"chatbot\"");
    }
    if (vk === "deepfake" &&
        (scenario.content === undefined || scenario.content === null)) {
      throw new AiDisclosureError("ai-disclosure/bad-scenario",
        "applyAll: scenario.content is required when kinds includes \"deepfake\"");
    }
    if (vk === "deepfake" &&
        (typeof scenario.contentType !== "string" || scenario.contentType.length === 0)) {
      throw new AiDisclosureError("ai-disclosure/bad-scenario",
        "applyAll: scenario.contentType is required (string) when kinds includes \"deepfake\"");
    }
  }
  // Shared opts forwarded to each per-kind call.
  var shared = {
    jurisdiction:  scenario.jurisdiction,
    language:      scenario.language,
    audit:         scenario.audit,
    correlationId: scenario.correlationId,
  };
  var out = { disclosures: {} };
  for (var i = 0; i < scenario.kinds.length; i += 1) {
    var kind = scenario.kinds[i];
    if (kind === "chatbot") {
      out.disclosures.chatbot = chatbot(scenario.session, Object.assign({
        placement: scenario.chatbotPlacement,
        requested: scenario.chatbotRequested,
      }, shared));
    } else if (kind === "deepfake") {
      out.disclosures.deepfake = deepfake(scenario.content, Object.assign({
        contentType: scenario.contentType,
        placement:   scenario.deepfakePlacement,
      }, shared));
    } else if (kind === "emotion") {
      out.disclosures.emotion = emotion(Object.assign({
        systemType: scenario.emotionSystemType,
      }, shared));
    }
  }
  return out;
}

module.exports = {
  chatbot:                  chatbot,
  deepfake:                 deepfake,
  emotion:                  emotion,
  applyAll:                 applyAll,
  AiDisclosureError:        AiDisclosureError,
  SUPPORTED_JURISDICTIONS:  Object.freeze(SUPPORTED_JURISDICTIONS.slice()),
  DEEPFAKE_CONTENT_TYPES:   Object.freeze(DEEPFAKE_CONTENT_TYPES.slice()),
};
