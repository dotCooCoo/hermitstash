"use strict";
/**
 * @module b.ai.input
 * @nav    AI
 * @title  AI Input Classifier
 *
 * @intro
 *   Prompt-injection + jailbreak classifier for operator input flowing
 *   into LLM prompts. OWASP LLM01:2025 + NIST COSAIS RFI. Pattern set
 *   covers explicit-override prompts, role-reset markers, persona
 *   jailbreaks, exfiltration callbacks, bidi / zero-width / control
 *   char features, and encoded-instruction smells (base64 / rot13 /
 *   markdown / HTML script).
 *
 *   Severity 3 = malicious-by-default; severity 2 = suspicious. Verdict
 *   is `malicious` on any severity-3 hit, `suspicious` on 2+ severity-2
 *   hits, otherwise `clean`.
 *
 * @card
 *   Prompt-injection + jailbreak classifier — OWASP LLM01:2025 + NIST COSAIS RFI. Pattern set + bidi / zero-width feature scan; verdict-driven refusal helper.
 */

var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var audit = require("./audit");
var { AiInputError } = require("./framework-error");

var SAMPLE_TRUNC = 80;                                                                       // sample truncation length, not bytes
var CONFIDENCE_BASE = 60;                                                                    // allow:raw-time-literal — confidence-score base 60; coincidental multiple-of-60, not a duration, C.TIME N/A

var PATTERNS = [
  { id: "ignore-prior-instructions", severity: 3, re:
    /\b(?:ignore|disregard|forget|bypass|override|skip|drop)\b[\s\S]{0,40}\b(?:prior|previous|above|all|earlier|prev|original|system|instructions?|prompt|context|rules?|directives?|guidelines?)\b/i },
  { id: "act-as-different-system",   severity: 3, re:
    /\byou\s+(?:are|will\s+be|must\s+be)\s+(?:now|from\s+now\s+on)?\s*(?:a|an)\s+\w{2,40}/i },
  { id: "jailbreak-persona",         severity: 3, re:
    /\b(?:DAN|do\s+anything\s+now|developer\s+mode|sudo\s+mode|jailbroken|unfiltered|uncensored|unrestricted)\b/i },
  { id: "role-reset-marker",         severity: 3, re:
    /<\s*\/?\s*(?:system|user|assistant|sys|im_(?:start|end)|\|im_(?:start|end)\|)\s*>/i },
  { id: "openai-system-tag",         severity: 3, re:
    /\b(?:<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\]|<\|user\|>|<\|assistant\|>|<\|system\|>)\b/ },
  { id: "tool-call-injection",       severity: 3, re:
    /\b(?:tool|function|action)\s*[:=]\s*["']?(?:exec|eval|read_file|exfil|leak|extract)\b/i },
  { id: "exfil-callback",            severity: 3, re:
    /\b(?:send|post|fetch|exfil|leak|paste|forward)\b[\s\S]{0,40}(?:secret|key|token|password|cred|env|\.ssh|private)/i },
  { id: "base64-marker-around-instructions", severity: 2, re:
    /(?:[A-Za-z0-9+/]{40,}={0,2})\s+(?:means|decodes?\s+to|=)/i },                          // regex repetition floor, not bytes
  { id: "rot13-shape",               severity: 2, re:
    /\b(?:rot13|rotcipher|cipher|caesar)\s*[:=]\s*[a-zA-Z]{20,}/i },
  { id: "markdown-injection",        severity: 2, re:
    /!\[[^\]]{0,40}\]\((?:javascript:|data:|file:)/i },
  { id: "html-script-shape",         severity: 2, re:
    /<script[\s>]|on\w+\s*=\s*["'][^"']*\b(?:fetch|xhr|eval|location)\b/i },
  { id: "stop-helping",              severity: 2, re:
    /\b(?:stop|cease|quit)\s+(?:helping|assisting|following)\b/i },
  { id: "now-instead",               severity: 2, re:
    /\b(?:instead|rather|now\s+do|new\s+task)\b[\s\S]{0,40}\b(?:of|than)\b/i },
];

function _featuresOf(input) {
  var bidi = 0, zw = 0, ctrl = 0;
  for (var i = 0; i < input.length; i += 1) {
    var cp = input.charCodeAt(i);
    if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) bidi++;
    else if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff || cp === 0x2060) zw++;
    else if (cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) ctrl++;
    else if (cp === 0x7f) ctrl++;
  }
  return {
    length:    input.length,
    lines:     input.split("\n").length,
    bidiCount: bidi,
    zwCount:   zw,
    ctrlCount: ctrl,
  };
}

/**
 * @primitive b.ai.input.classify
 * @signature b.ai.input.classify(input, opts?)
 * @since     0.8.10
 * @status    stable
 * @related   b.ai.input.refuseIfMalicious, b.guardHtml, b.mcp.toolResult.sanitize
 *
 * Classify operator-supplied prompt text against the injection /
 * jailbreak pattern set. Returns
 * `{ verdict, signals, features, confidence }`.
 *
 * @opts
 *   maxBytes:    number,      // default 64 KiB; throws on overflow
 *   audit:       boolean,      // default true; emit ai.input.classify event
 *   errorClass:  ErrorClass,   // override the thrown class on bad input
 *
 * @example
 *   var v = b.ai.input.classify("Ignore all prior instructions...");
 *   v.verdict;     // → "malicious"
 *   v.signals[0];  // → { id: "ignore-prior-instructions", severity: 3 }
 */
function classify(input, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || AiInputError;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes, "aiInput.classify: opts.maxBytes", errorClass, "BAD_MAX_BYTES");
  var maxBytes = opts.maxBytes || C.BYTES.kib(64);
  var auditOn = opts.audit !== false;

  if (typeof input !== "string") {
    throw errorClass.factory("ai-input/bad-input",
      "aiInput.classify: input must be a string");
  }
  var byteLen = Buffer.byteLength(input, "utf8");
  if (byteLen > maxBytes) {
    throw errorClass.factory("ai-input/input-too-large",
      "aiInput.classify: input exceeds " + maxBytes + " bytes (got " + byteLen + ")");
  }

  var features = _featuresOf(input);
  var signals = [];

  for (var i = 0; i < PATTERNS.length; i += 1) {
    var p = PATTERNS[i];
    var m = p.re.exec(input);
    if (m) {
      signals.push({
        id:       p.id,
        severity: p.severity,
        sample:   m[0].slice(0, SAMPLE_TRUNC),
      });
    }
  }

  if (features.bidiCount > 0)  signals.push({ id: "bidi-controls",       severity: 2, sample: null });
  if (features.zwCount > 5)    signals.push({ id: "zero-width-density",  severity: 2, sample: null });
  if (features.ctrlCount > 0)  signals.push({ id: "control-chars",       severity: 2, sample: null });

  var sev3 = 0, sev2 = 0;
  for (var j = 0; j < signals.length; j += 1) {
    if (signals[j].severity === 3) sev3++;
    else if (signals[j].severity === 2) sev2++;
  }
  var verdict = sev3 > 0 ? "malicious" : (sev2 >= 2 ? "suspicious" : "clean");
  var confidence = sev3 === 0 && sev2 === 0 ? 0 : Math.min(100, CONFIDENCE_BASE + sev3 * 15 + sev2 * 5);                                // confidence ceiling 100, not bytes/seconds

  if (auditOn && verdict !== "clean") {
    audit.safeEmit({
      action:   "aiinput.classify",
      outcome:  verdict === "malicious" ? "denied" : "warning",
      metadata: {
        verdict:    verdict,
        signalIds:  signals.map(function (s) { return s.id; }),
        confidence: confidence,
        length:     features.length,
      },
    });
  }

  return {
    verdict:    verdict,
    signals:    signals,
    features:   features,
    confidence: confidence,
  };
}

/**
 * @primitive b.ai.input.refuseIfMalicious
 * @signature b.ai.input.refuseIfMalicious(input, opts?)
 * @since     0.8.10
 * @status    stable
 * @related   b.ai.input.classify
 *
 * Run `classify` and throw on `verdict === "malicious"` (severity-3
 * pattern hit) — return the classification result otherwise. Operator
 * convenience wrapper for handlers that want a single fail-closed
 * call before forwarding to an LLM.
 *
 * @opts
 *   maxBytes:    number,      // default 64 KiB
 *   audit:       boolean,      // default true
 *   errorClass:  ErrorClass,   // override the thrown class
 *
 * @example
 *   try { b.ai.input.refuseIfMalicious(req.body.prompt); }
 *   catch (e) { res.statusCode = 400; res.end(e.message); }
 */
function refuseIfMalicious(input, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || AiInputError;
  var result = classify(input, opts);
  if (result.verdict === "malicious") {
    throw errorClass.factory("ai-input/malicious-input",
      "aiInput: input flagged as malicious (signals: " +
      result.signals.map(function (s) { return s.id; }).join(", ") + ")");
  }
  return result;
}

module.exports = {
  classify:           classify,
  refuseIfMalicious:  refuseIfMalicious,
  PATTERN_IDS:        PATTERNS.map(function (p) { return p.id; }),
};
