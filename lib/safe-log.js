/**
 * Safe logging helpers — keep secret material out of console / log sinks (CWE-532).
 *
 * Two postures, chosen per call site:
 *
 *   scrub(msg)  — redact credential-shaped substrings from a free-text error message
 *                 before it reaches a sink. Backed by b.redact.redactText (word-boundary
 *                 matching of PEM blocks, JWTs, AWS keys, URL-userinfo passwords, bearer
 *                 tokens, key=secret assignments, SSN/EIN, Luhn PANs). Use for STRUCTURAL
 *                 errors (crypto/wrap/decrypt failures about lengths, magic bytes, Argon2
 *                 params, "passphrase rejected") that are operator-actionable and never
 *                 carry a secret — the redactor is a defensive barrier against a future
 *                 credential-shaped substring, and preserves the useful message.
 *
 *   code(err)   — return ONLY a non-secret error identifier (err.code || err.name).
 *                 Use for errors thrown by operations that PARSE or UNWRAP raw secret key
 *                 material (JSON.parse of a decrypted keypair, envelope/vault unwrap),
 *                 where the error text itself can embed raw high-entropy key bytes that
 *                 scrub() cannot detect. Never log the message or stack from those paths.
 */
var b = require("./vendor/blamejs");

function scrub(msg) {
  return b.redact.redactText(String(msg == null ? "" : msg));
}

function code(err) {
  return (err && (err.code || err.name)) || "unknown";
}

module.exports = { scrub: scrub, code: code };
