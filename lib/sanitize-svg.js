/**
 * SVG sanitizer — strips script tags, event handlers, and dangerous elements
 * before inline preview. Layered defense — the primary control is the strict
 * CSP applied to SVG-serving routes (default-src 'none' + no script-src), which
 * blocks JS execution even if this sanitizer misses something. This pass
 * catches common regex-evadable patterns that would otherwise survive:
 *
 *   - <script/x> (no space after tag name)
 *   - <svg/onload=x> (slash instead of whitespace before the handler)
 *   - &#x6F;nload= (numeric-entity-encoded attribute names)
 *   - <style> blocks with CSS url(javascript:...) payloads
 *   - nested <svg> embedded via data:image/svg+xml;base64,...
 *
 * Intentionally a denylist, not a full parser. Do not rely on this as the sole
 * XSS defense — the route-level CSP must remain in place.
 */

// Decode common HTML entities BEFORE matching so obfuscated attack patterns
// surface as plain text. Covers hex, decimal, and the named entities most
// commonly used to hide attributes: &#x6F;nload → onload, &lt;script → <script.
var ENTITY_RE = /&#x([0-9a-f]+);|&#([0-9]+);|&(amp|lt|gt|quot|apos);/gi;
function decodeEntities(s) {
  return s.replace(ENTITY_RE, function (match, hex, dec, named) {
    try {
      if (hex) return String.fromCodePoint(parseInt(hex, 16));
      if (dec) return String.fromCodePoint(parseInt(dec, 10));
    } catch (_e) { return match; }
    if (named === "amp") return "&";
    if (named === "lt") return "<";
    if (named === "gt") return ">";
    if (named === "quot") return '"';
    if (named === "apos") return "'";
    return match;
  });
}

// Tags that are either scripting vectors (script, iframe, foreignObject),
// CSS injection points (style), or SMIL animations that can trigger JS via
// begin/end handlers.
var DANGEROUS_TAG_NAMES = "script|iframe|object|embed|foreignObject|style|link|meta|set|animate|animateTransform|animateMotion|filter|feImage|handler|listener";

// Balanced open+content+close (best-effort — SVG content that already has a
// close tag removes both; standalone opens are caught by the self-close pass).
// Word boundary \b matches after the tag name even when the next char is / or a space.
var BALANCED_DANGEROUS = new RegExp("<(" + DANGEROUS_TAG_NAMES + ")\\b[\\s\\S]*?<\\/\\1\\s*>", "gi");
var SELF_CLOSE_DANGEROUS = new RegExp("<(?:" + DANGEROUS_TAG_NAMES + ")\\b[^>]*>", "gi");
var ORPHAN_CLOSE = new RegExp("<\\/(?:" + DANGEROUS_TAG_NAMES + ")\\s*>", "gi");

// Event handlers — boundary char (whitespace or slash) before on[letters]=.
// Covers <svg onload=..>, <svg/onload=..>, <svg  onload = "..">
var EVENT_HANDLERS = /[\s/]+on[a-z][a-z0-9]*\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)/gi;

// Dangerous URI schemes on any attribute. Covers href, xlink:href, src,
// action, formaction, and the SVG-specific style="…url(…)". Matches the
// whole attribute so the mangled remainder doesn't create a new injection.
var DANGEROUS_URI_ATTR = /[\s/]+(?:href|xlink:href|src|action|formaction|poster|background|codebase)\s*=\s*(?:"[^"]*(?:javascript|vbscript|data\s*:\s*text|data\s*:\s*image\/svg)[^"]*"|'[^']*(?:javascript|vbscript|data\s*:\s*text|data\s*:\s*image\/svg)[^']*'|[^\s>]*(?:javascript|vbscript|data\s*:\s*text|data\s*:\s*image\/svg)[^\s>]*)/gi;

// Strip the style attribute wholesale — CSS in SVG context enables
// url(javascript:…), expression(…), and import tricks that are not worth
// parsing at this layer.
var STYLE_ATTR = /[\s/]+style\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)/gi;

var COMMENTS = /<!--[\s\S]*?-->/g;
var CDATA = /<!\[CDATA\[[\s\S]*?\]\]>/g;
// Processing instructions and doctypes — allow <?xml ...?> at the start (declared document)
// but strip other <? ... ?> and <!DOCTYPE ...>.
var PROCESSING_INSTRUCTION = /<\?(?!xml\b)[\s\S]*?\?>/g;
var DOCTYPE = /<!DOCTYPE[\s\S]*?>/gi;

function sanitizeSvg(svgString) {
  if (!svgString || typeof svgString !== "string") return "";
  var clean = decodeEntities(svgString);
  // Iterate until the string stabilizes — stripping one layer can unmask another
  // (e.g. `<scr<script>ipt>` collapses after one pass). Cap at 5 iterations to
  // avoid pathological inputs that grow between passes (they shouldn't, but belt-and-braces).
  for (var i = 0; i < 5; i++) {
    var before = clean;
    clean = clean.replace(COMMENTS, "");
    clean = clean.replace(CDATA, "");
    clean = clean.replace(PROCESSING_INSTRUCTION, "");
    clean = clean.replace(DOCTYPE, "");
    clean = clean.replace(BALANCED_DANGEROUS, "");
    clean = clean.replace(SELF_CLOSE_DANGEROUS, "");
    clean = clean.replace(ORPHAN_CLOSE, "");
    clean = clean.replace(EVENT_HANDLERS, "");
    clean = clean.replace(DANGEROUS_URI_ATTR, "");
    clean = clean.replace(STYLE_ATTR, "");
    if (clean === before) break;
  }
  return clean;
}

module.exports = { sanitizeSvg };
