/**
 * SVG sanitizer — strips script tags, event handlers, and dangerous
 * elements before inline preview. Layered defense: the primary control
 * is the strict CSP applied to SVG-serving routes (default-src 'none' +
 * no script-src), which blocks JS execution even if this sanitizer
 * misses something. This pass catches regex-evadable patterns that
 * would otherwise survive into the rendered DOM.
 *
 * Backed by blamejs's b.guardSvg.sanitize (balanced profile) — covers
 * the same denylist surface as HermitStash's previous regex sweep
 * plus SMIL animation attributeName allowlists, billion-laughs / DTD
 * entity expansion, SVGZ recognition, and codepoint-class threats.
 *
 * HS-local semantics preserved: non-string / null input returns "" so
 * upload pipelines can pass-through unsanitized payloads (e.g. binary)
 * without the throw blamejs uses for hard-input validation contexts.
 */
var b = require("./vendor/blamejs");

function sanitizeSvg(svgString) {
  if (!svgString || typeof svgString !== "string") return "";
  try {
    return b.guardSvg.sanitize(svgString);
  } catch (_e) {
    return "";
  }
}

module.exports = { sanitizeSvg };
