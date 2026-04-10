/**
 * SVG sanitizer — strips script tags, event handlers, and dangerous elements.
 * Returns safe SVG string for inline preview.
 */

var DANGEROUS_TAGS = /(<script[\s>][\s\S]*?<\/script>|<iframe[\s>][\s\S]*?<\/iframe>|<object[\s>][\s\S]*?<\/object>|<embed[\s>][\s\S]*?<\/embed>|<foreignObject[\s>][\s\S]*?<\/foreignObject>)/gi;
var EVENT_HANDLERS = /\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)/gi;
var HREF_JS = /\s+(href|xlink:href)\s*=\s*["']?\s*javascript:/gi;
var DATA_URI_SCRIPT = /\s+(href|xlink:href|src)\s*=\s*["']?\s*data:text\/(html|javascript)/gi;

function sanitizeSvg(svgString) {
  if (!svgString || typeof svgString !== "string") return "";
  var clean = svgString;
  clean = clean.replace(DANGEROUS_TAGS, "");
  clean = clean.replace(EVENT_HANDLERS, "");
  clean = clean.replace(HREF_JS, "");
  clean = clean.replace(DATA_URI_SCRIPT, "");
  return clean;
}

module.exports = { sanitizeSvg };
